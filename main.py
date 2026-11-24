"""Vigil V2 entry point: wires ingestion, engine and output together."""

import argparse
import asyncio
import logging

from src.core.queue_manager import QueueManager
from src.engine.rules_brand import load_brand_index, load_typosquat_index
from src.engine.scorer import Scorer
from src.engine.whitelist import Whitelist
from src.ingestion.certstream_ws import DEFAULT_URL, CertstreamClient
from src.output.dispatcher import AlertDispatcher
from src.output.formatter import AlertFormatter
from src.output.stream_server import AlertBroadcaster, StreamServer

logger = logging.getLogger("vigil")


async def engine_worker(
    queue: QueueManager,
    scorer: Scorer,
    formatter: AlertFormatter,
    dispatcher: AlertDispatcher,
) -> None:
    while True:
        event = await queue.get()
        try:
            result = scorer.evaluate(event)
            if scorer.is_suspicious(result):
                await dispatcher.dispatch(formatter.to_json(result))
        except Exception:
            logger.exception("Processing failed for %s", event.domain)
        finally:
            queue.task_done()


async def stats_reporter(queue: QueueManager, interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        logger.info("queue=%d dropped=%d", queue.qsize(), queue.dropped)


async def run(args: argparse.Namespace) -> None:
    await asyncio.to_thread(load_brand_index)
    await asyncio.to_thread(load_typosquat_index)
    queue = QueueManager(maxsize=args.queue_size)
    scorer = Scorer(threshold=args.threshold, whitelist=Whitelist.from_file(args.whitelist))
    formatter = AlertFormatter()
    broadcaster = AlertBroadcaster()
    server = StreamServer(broadcaster, host=args.host, port=args.port)
    dispatcher = AlertDispatcher(broadcaster=broadcaster)
    client = CertstreamClient(queue, url=args.url)

    tasks = [
        asyncio.create_task(client.run(), name="ingestion"),
        asyncio.create_task(stats_reporter(queue, args.stats_interval), name="stats"),
        *(
            asyncio.create_task(
                engine_worker(queue, scorer, formatter, dispatcher),
                name=f"engine-{i}",
            )
            for i in range(args.workers)
        ),
    ]

    await server.start()
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await server.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Vigil V2 - phishing detection from the CertStream feed")
    parser.add_argument("--url", default=DEFAULT_URL, help="CertStream server URL")
    parser.add_argument("--threshold", type=int, default=50, help="minimum score to raise an alert")
    parser.add_argument("--whitelist", default=None, help="YAML file of whitelist regexes")
    parser.add_argument("--host", default="127.0.0.1", help="stream server bind address")
    parser.add_argument("--port", type=int, default=8000, help="stream server port")
    parser.add_argument("--queue-size", type=int, default=10000, help="queue capacity")
    parser.add_argument("--workers", type=int, default=1, help="number of engine consumers")
    parser.add_argument("--stats-interval", type=float, default=60.0, help="stats reporting interval (s)")
    parser.add_argument("--verbose", action="store_true", help="enable DEBUG logs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        logger.info("Shutdown requested")


if __name__ == "__main__":
    main()
