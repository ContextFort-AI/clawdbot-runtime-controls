from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def load_known_domains():
    domains = set()
    path = DATA_DIR / "known_domains.csv"
    if not path.exists():
        return domains

    for line in path.read_text().splitlines()[1:]:
        if line.strip():
            domain = line.split(",")[0].strip()
            if domain:
                domains.add(domain.lower())

    return domains


def load_confusables():
    confusables = {}
    path = DATA_DIR / "confusables.txt"
    if not path.exists():
        return confusables

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("#")[0].strip().split()
        if len(parts) >= 2:
            try:
                confusable_cp = int(parts[0], 16)
                target_cp = int(parts[1], 16)
                confusables[chr(confusable_cp)] = chr(target_cp)
            except (ValueError, IndexError):
                continue

    return confusables


_known_domains = None
_confusables = None


def get_known_domains():
    global _known_domains
    if _known_domains is None:
        _known_domains = load_known_domains()
    return _known_domains


def get_confusables():
    global _confusables
    if _confusables is None:
        _confusables = load_confusables()
    return _confusables


def skeleton(s):
    confusables = get_confusables()
    result = []
    for char in s:
        result.append(confusables.get(char, char))
    return "".join(result)


def is_known_domain(domain):
    return domain.lower() in get_known_domains()
