"""Contextual heuristics not tied to a specific brand."""

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from src.core.queue_manager import CertEvent
from src.engine.domain_parser import ParsedDomain
from src.engine.rules_brand import _is_legit_domain, load_brand_index

KEYWORDS_FILE = Path(__file__).resolve().parents[1] / "data" / "phishing_keywords.yaml"
KEYWORD_SCORE = 10
PATTERN_SCORE = 20
MAX_KEYWORD_SCORE = 40
MIN_SUBSTRING_LENGTH = 5

_LABEL_SEPARATORS = re.compile(r"[.\-_]")
_NON_ALNUM = re.compile(r"[^a-z0-9]")


@dataclass(frozen=True, slots=True)
class KeywordIndex:
    """Lookup structures built from the phishing keyword referential."""

    entries: dict[str, tuple[str, int]]
    substring_pattern: re.Pattern | None
    token_keys: frozenset[str]


def _normalize(text: str) -> str:
    """Lowercase and drop non-alphanumeric characters."""
    return _NON_ALNUM.sub("", text.lower())


@lru_cache(maxsize=1)
def load_keyword_index() -> KeywordIndex:
    """Load the keyword referential once. Short keys only match whole labels.

    A multi-word pattern outweighs a plain keyword that normalizes to the same key.
    """
    with KEYWORDS_FILE.open(encoding="utf-8") as fh:
        document = yaml.safe_load(fh)

    entries: dict[str, tuple[str, int]] = {}
    for section, score in (("keywords", KEYWORD_SCORE), ("patterns", PATTERN_SCORE)):
        for words in (document.get(section) or {}).values():
            for word in words:
                key = _normalize(word)
                if not key:
                    continue
                current = entries.get(key)
                if current is None or score > current[1]:
                    entries[key] = (word.lower(), score)

    long_keys = sorted(
        (k for k in entries if len(k) >= MIN_SUBSTRING_LENGTH), key=len, reverse=True
    )
    pattern = re.compile("|".join(map(re.escape, long_keys))) if long_keys else None
    short_keys = frozenset(k for k in entries if len(k) < MIN_SUBSTRING_LENGTH)
    return KeywordIndex(entries, pattern, short_keys)


def check_keywords(parsed: ParsedDomain, event: CertEvent) -> tuple[int, str]:
    """Spot phishing keywords in the subdomain and root of the FQDN.

    Long keywords match as substrings of the label text with separators removed,
    which catches glued words such as ``paypalsecurelogin``. Short keywords only
    match a whole label token. The public suffix is ignored, and so are official
    brand domains. Each distinct keyword scores ``KEYWORD_SCORE`` and each
    multi-word pattern ``PATTERN_SCORE``, capped at ``MAX_KEYWORD_SCORE`` so that
    keywords alone never reach the default alert threshold.

    Args:
        parsed: Domain split into root, subdomains and TLD.
        event: Originating event (unused).

    Returns:
        A ``(score, reason)`` tuple. ``(0, "")`` if no keyword is found.
    """
    if _is_legit_domain(parsed.fqdn.lower(), load_brand_index().legit_domains):
        return 0, ""

    text = ".".join(part for part in (parsed.subdomain, parsed.root) if part).lower()
    if not text:
        return 0, ""

    index = load_keyword_index()
    keys: set[str] = set()
    if index.substring_pattern is not None:
        joined = _LABEL_SEPARATORS.sub("", text)
        keys.update(m.group() for m in index.substring_pattern.finditer(joined))
    tokens = {_normalize(t) for t in _LABEL_SEPARATORS.split(text)}
    keys.update(tokens & index.token_keys)

    if not keys:
        return 0, ""

    matched = sorted(keys, key=lambda k: (-index.entries[k][1], k))
    score = min(sum(index.entries[k][1] for k in matched), MAX_KEYWORD_SCORE)
    names = ", ".join(index.entries[k][0] for k in matched)
    return score, f"phishing keywords in domain: {names}"
