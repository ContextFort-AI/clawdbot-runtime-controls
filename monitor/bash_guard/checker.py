from .checks import ALL_CHECKS


def check_command(command: str):
    """
    Returns (rule_id, description) if threat detected, None otherwise.
    """
    for check in ALL_CHECKS:
        result = check(command)
        if result:
            return result

    return None
