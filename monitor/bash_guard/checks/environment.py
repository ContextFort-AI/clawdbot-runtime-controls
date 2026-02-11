from ..patterns import PROXY_ENV_VARS


def check_proxy_env_set(command):
    for var in PROXY_ENV_VARS:
        patterns = [
            f"export {var}=",
            f"{var}=",
            f"set {var}=",
        ]
        for pattern in patterns:
            if pattern in command:
                return ("proxy_env_set", f"Proxy environment variable being set: {var}")

    return None
