def split_commands(command):
    """
    Split on && ; || while respecting quotes and escapes.
    Note: Does not handle $() or () subshells.
    """
    result = []
    current = []
    i = 0
    in_single = False
    in_double = False

    while i < len(command):
        char = command[i]

        # Backslash escape (not in single quotes - they're literal there)
        if char == '\\' and not in_single and i + 1 < len(command):
            current.append(char)
            current.append(command[i + 1])
            i += 2
            continue

        if char == '"' and not in_single:
            in_double = not in_double
            current.append(char)
        elif char == "'" and not in_double:
            in_single = not in_single
            current.append(char)
        elif not in_single and not in_double:
            if command[i:i+2] in ('&&', '||'):
                if current:
                    result.append(''.join(current).strip())
                    current = []
                i += 2
                continue
            elif char == ';':
                if current:
                    result.append(''.join(current).strip())
                    current = []
            else:
                current.append(char)
        else:
            current.append(char)
        i += 1

    if current:
        result.append(''.join(current).strip())

    return [c for c in result if c] or [command]


def levenshtein(a, b):
    m, n = len(a), len(b)
    if m == 0:
        return n
    if n == 0:
        return m

    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(
                dp[i-1][j] + 1,
                dp[i][j-1] + 1,
                dp[i-1][j-1] + cost
            )

    return dp[m][n]


def extract_host_from_url(url):
    try:
        if "://" in url:
            rest = url.split("://")[1]
        else:
            rest = url

        if "@" in rest.split("/")[0]:
            rest = rest.split("@")[-1]

        host_part = rest.split("/")[0]

        if ":" in host_part:
            host_part = host_part.rsplit(":", 1)[0]

        return host_part
    except (IndexError, ValueError):
        return None
