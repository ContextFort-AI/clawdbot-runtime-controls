import re
import regex
from ..patterns import (
    LOOKALIKE_TLDS,
    INVALID_HOST_CHARS,
    UNICODE_DOTS,
)
from ..data import get_known_domains, skeleton, is_known_domain
from .utils import levenshtein, extract_host_from_url


def check_non_ascii_hostname(command):
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = extract_host_from_url(url)
        if host and any(ord(c) > 127 for c in host):
            return ("non_ascii_hostname", f"Non-ASCII characters in hostname: {host}")

    return None


def check_mixed_script_in_label(command):
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = extract_host_from_url(url)
        if not host:
            continue

        for label in host.split("."):
            if not label:
                continue

            scripts = set()
            for char in label:
                if char == "-" or char.isdigit():
                    continue

                if regex.match(r'\p{Script=Latin}', char):
                    scripts.add('Latin')
                elif regex.match(r'\p{Script=Cyrillic}', char):
                    scripts.add('Cyrillic')
                elif regex.match(r'\p{Script=Greek}', char):
                    scripts.add('Greek')
                elif regex.match(r'\p{Script=Han}', char):
                    scripts.add('Han')
                elif regex.match(r'\p{Script=Hiragana}', char):
                    scripts.add('Hiragana')
                elif regex.match(r'\p{Script=Katakana}', char):
                    scripts.add('Katakana')
                elif regex.match(r'\p{Script=Arabic}', char):
                    scripts.add('Arabic')
                elif regex.match(r'\p{Script=Hebrew}', char):
                    scripts.add('Hebrew')

            if len(scripts) > 1:
                return ("mixed_script_in_label", f"Mixed scripts in hostname label '{label}': {scripts}")

    return None


def check_userinfo_trick(command):
    urls = re.findall(r'https?://([^@/\s]+)@[^\s]+', command)

    for userinfo in urls:
        if "." in userinfo:
            return ("userinfo_trick", f"Domain-like userinfo in URL: {userinfo}@...")

    return None


def check_confusable_domain(command):
    known_domains = get_known_domains()
    if not known_domains:
        return None

    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = extract_host_from_url(url)
        if not host:
            continue

        host_lower = host.lower()

        if host_lower in known_domains:
            continue

        host_skeleton = skeleton(host_lower)

        for known in known_domains:
            if host_skeleton == known and host_lower != known:
                return ("confusable_domain", f"Domain '{host}' is visually similar to known domain '{known}'")

            if len(known) >= 8:
                len_diff = abs(len(host_lower) - len(known))
                if len_diff <= 3 and levenshtein(host_lower, known) == 1:
                    return ("confusable_domain", f"Domain '{host}' is 1 edit from known domain '{known}'")

    return None


def check_invalid_host_chars(command):
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = extract_host_from_url(url)
        if not host:
            continue

        for char in host:
            if char in INVALID_HOST_CHARS:
                return ("invalid_host_chars", f"Invalid character '{char}' in hostname")
            if char in UNICODE_DOTS:
                return ("invalid_host_chars", f"Unicode dot character in hostname: U+{ord(char):04X}")
            if ord(char) < 0x20 or char.isspace():
                return ("invalid_host_chars", "Control character or whitespace in hostname")

    return None


def check_trailing_dot_whitespace(command):
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = extract_host_from_url(url)
        if not host:
            continue

        if host.endswith("."):
            return ("trailing_dot_whitespace", "Trailing dot in hostname")
        if host[-1:].isspace():
            return ("trailing_dot_whitespace", "Trailing whitespace in hostname")

    return None


def check_non_standard_port(command):
    standard_ports = {80, 443, 22, 9418}

    url_port_pattern = r'https?://([^:/\s]+):(\d+)'
    matches = re.findall(url_port_pattern, command)

    for host, port_str in matches:
        try:
            port = int(port_str)
        except ValueError:
            continue

        if port in standard_ports:
            continue

        if is_known_domain(host.lower()):
            return ("non_standard_port", f"Non-standard port {port} on known domain '{host}'")

    return None


def check_lookalike_tld(command):
    urls = re.findall(r'https?://[^\s]+', command)
    for url in urls:
        host = url.split("://")[1].split("/")[0].split(":")[0].lower()
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in LOOKALIKE_TLDS:
            return ("lookalike_tld", f"Lookalike TLD detected: .{tld}")

    return None


def check_punycode_domain(command):
    if "xn--" in command.lower():
        return ("punycode_domain", "Punycode domain detected (potential homograph)")

    return None


def check_raw_ip_url(command):
    ipv4_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ipv4_pattern, command):
        return ("raw_ip_url", "URL uses raw IP address instead of domain")

    return None
