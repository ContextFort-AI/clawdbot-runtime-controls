import re
from ..patterns import (
    INTERPRETERS,
    INSECURE_TLS_FLAGS,
    URL_SHORTENERS,
    CURL_UPLOAD_FLAGS,
    WGET_UPLOAD_FLAGS,
)
from ..data import is_known_domain
from .utils import split_commands, extract_host_from_url


def check_insecure_tls_flags(command):
    words = command.split()
    for word in words:
        clean = word.strip("'\"")
        if clean in INSECURE_TLS_FLAGS:
            return ("insecure_tls_flags", f"Insecure TLS flag: {clean}")

    return None


def check_shortened_url(command):
    command_lower = command.lower()
    for shortener in URL_SHORTENERS:
        if shortener in command_lower:
            return ("shortened_url", f"Shortened URL detected: {shortener}")

    return None


def _check_plain_http_to_sink_single(command):
    """Check a single command for plain HTTP piped to sink."""
    if "http://" not in command.lower():
        return None

    if "|" not in command:
        return None

    parts = command.split("|")
    for part in parts[1:]:
        words = part.strip().split()
        if words:
            cmd = words[0].lower().rsplit("/", 1)[-1]
            if cmd in INTERPRETERS or cmd in ("sudo", "env"):
                return ("plain_http_to_sink", "Plain HTTP URL piped to interpreter")

    return None


def check_plain_http_to_sink(command):
    """Check for plain HTTP to sink, handling && and ; separators."""
    for subcmd in split_commands(command):
        result = _check_plain_http_to_sink_single(subcmd)
        if result:
            return result
    return None


def _check_schemeless_to_sink_single(command):
    """Check a single command for schemeless URL piped to sink."""
    if "|" not in command:
        return None

    schemeless_pattern = r'(?<!\w://)(?<!\w://www\.)([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/\S+'

    parts = command.split("|")
    first_part = parts[0]

    if re.search(schemeless_pattern, first_part):
        for part in parts[1:]:
            words = part.strip().split()
            if words:
                cmd = words[0].lower().rsplit("/", 1)[-1]
                if cmd in INTERPRETERS or cmd in ("sudo", "env"):
                    return ("schemeless_to_sink", "Schemeless URL piped to interpreter")

    return None


def check_schemeless_to_sink(command):
    """Check for schemeless URL to sink, handling && and ; separators."""
    for subcmd in split_commands(command):
        result = _check_schemeless_to_sink_single(subcmd)
        if result:
            return result
    return None


_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _check_curl_upload_single(command):
    """Check a single command for curl/wget uploading data to unknown hosts."""
    words = command.split()
    if not words:
        return None

    cmd = words[0].rsplit("/", 1)[-1].lower()
    if cmd not in ("curl", "wget"):
        return None

    upload_flags = CURL_UPLOAD_FLAGS if cmd == "curl" else WGET_UPLOAD_FLAGS

    has_upload_flag = False
    for word in words[1:]:
        clean = word.strip("'\"")
        # Exact match: -d, --data, etc.
        if clean in upload_flags:
            has_upload_flag = True
            break
        # Prefix match for flag=value: --data=foo, --post-file=secrets.txt
        for flag in upload_flags:
            if clean.startswith(flag + "="):
                has_upload_flag = True
                break
        if has_upload_flag:
            break

    if not has_upload_flag:
        return None

    # Extract URL and check host
    for word in words[1:]:
        clean = word.strip("'\"")
        if re.match(r'https?://', clean, re.IGNORECASE):
            host = extract_host_from_url(clean)
            if not host:
                continue
            host_lower = host.lower()
            if host_lower in _LOCALHOST_HOSTS:
                return None
            # Check full host first (e.g. api.github.com), then parent domain
            if is_known_domain(host_lower):
                return None
            parts = host_lower.split(".")
            if len(parts) > 2:
                parent = ".".join(parts[-2:])
                if is_known_domain(parent):
                    return None
            return (
                "curl_upload_to_unknown",
                f"Data upload via {cmd} to unknown host: {host}",
            )

    return None


def check_curl_upload(command):
    """Check for curl/wget data uploads to unknown hosts, handling && and ; separators."""
    for subcmd in split_commands(command):
        result = _check_curl_upload_single(subcmd)
        if result:
            return result
    return None
