import re
from ..patterns import KNOWN_SENSITIVE_PATHS
from .utils import levenshtein


def check_non_ascii_path(command):
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        try:
            parts = url.split("://")[1].split("/", 1)
            if len(parts) < 2:
                continue
            path = "/" + parts[1]
        except IndexError:
            continue

        if any(ord(c) > 127 for c in path):
            return ("non_ascii_path", "Non-ASCII characters in URL path")

    return None


def check_homoglyph_in_path(command):
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        try:
            path = url.split("://")[1].split("/", 1)
            if len(path) < 2:
                continue
            path = "/" + path[1]
        except IndexError:
            continue

        for segment in path.split("/"):
            if not segment:
                continue

            has_ascii = any(c.isascii() and c.isalpha() for c in segment)
            has_non_ascii = any(ord(c) > 127 for c in segment)

            if has_ascii and has_non_ascii:
                segment_lower = segment.lower()
                for known in KNOWN_SENSITIVE_PATHS:
                    if levenshtein(segment_lower, known) <= 2:
                        return ("homoglyph_in_path", f"Potential homoglyph in path: '{segment}' looks like '{known}'")

    return None


def check_double_encoding(command):
    if "%25" in command:
        if re.search(r'%25[0-9a-fA-F]{2}', command):
            return ("double_encoding", "Double-encoded URL path detected (%25XX)")

    return None
