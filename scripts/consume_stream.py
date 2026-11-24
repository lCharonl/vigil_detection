"""Read the Vigil alert stream, print each alert and save it to a JSON Lines file.

The output file is emptied at every start.
"""

import argparse
import sys
import time
import urllib.error
import urllib.request

DEFAULT_URL = "http://localhost:8000/stream"
DEFAULT_OUTPUT = "alerts.jsonl"
RECONNECT_DELAY = 5.0


def consume(url: str, output: str) -> None:
    """Stream alerts forever, reconnecting after each disconnection."""
    with open(output, "w", encoding="utf-8") as out:
        while True:
            try:
                with urllib.request.urlopen(url) as response:
                    print(f"Connected to {url}", file=sys.stderr)
                    for raw in response:
                        line = raw.decode("utf-8").rstrip("\n")
                        if not line.startswith("data:"):
                            continue
                        alert = line[len("data:"):].strip()
                        print(alert, flush=True)
                        out.write(alert + "\n")
                        out.flush()
            except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
                print(f"Connection lost ({exc}), retrying in {RECONNECT_DELAY}s", file=sys.stderr)
            time.sleep(RECONNECT_DELAY)


def main() -> None:
    parser = argparse.ArgumentParser(description="Save the Vigil alert stream to a file")
    parser.add_argument("--url", default=DEFAULT_URL, help="Vigil stream URL")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="JSON Lines output file")
    args = parser.parse_args()
    try:
        consume(args.url, args.output)
    except KeyboardInterrupt:
        print("Stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
