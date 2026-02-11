import re
from ..patterns import (
    TRUSTED_DOCKER_REGISTRIES,
    TRUSTED_PIP_HOSTS,
    TRUSTED_NPM_HOSTS,
    WEB3_INDICATORS,
    POPULAR_REPOS,
)
from .utils import levenshtein


def check_docker_untrusted_registry(command):
    words = command.split()
    if len(words) < 3:
        return None

    cmd = words[0].lower()
    if cmd not in ("docker", "podman", "nerdctl"):
        return None

    subcmd = words[1].lower()
    if subcmd not in ("pull", "run", "create"):
        return None

    for word in words[2:]:
        if word.startswith("-"):
            continue

        if "/" in word and ":" not in word.split("/")[0]:
            registry = word.split("/")[0].lower()
            if registry not in TRUSTED_DOCKER_REGISTRIES:
                trusted = any(registry.endswith(f".{r}") for r in TRUSTED_DOCKER_REGISTRIES)
                if not trusted and "." in registry:
                    return ("docker_untrusted_registry", f"Docker image from untrusted registry: {registry}")
        break

    return None


def check_pip_url_install(command):
    words = command.split()
    if len(words) < 2:
        return None

    cmd = words[0].lower()
    if cmd not in ("pip", "pip3"):
        return None

    if "install" not in [w.lower() for w in words]:
        return None

    urls = re.findall(r'https?://([^/\s]+)', command)
    for host in urls:
        host_lower = host.lower()
        if host_lower not in TRUSTED_PIP_HOSTS and not host_lower.endswith(".pypi.org"):
            return ("pip_url_install", f"pip install from non-PyPI source: {host}")

    for i, word in enumerate(words):
        if word in ("--index-url", "-i", "--extra-index-url"):
            if i + 1 < len(words):
                url = words[i + 1]
                match = re.search(r'https?://([^/\s]+)', url)
                if match:
                    host = match.group(1).lower()
                    if host not in TRUSTED_PIP_HOSTS and not host.endswith(".pypi.org"):
                        return ("pip_url_install", f"pip using non-PyPI index: {host}")

    return None


def check_npm_url_install(command):
    words = command.split()
    if len(words) < 2:
        return None

    cmd = words[0].lower()
    if cmd not in ("npm", "npx", "yarn", "pnpm"):
        return None

    if "install" not in [w.lower() for w in words] and "add" not in [w.lower() for w in words]:
        return None

    for word in words:
        if ".tgz" in word or "/npm/" in word:
            match = re.search(r'https?://([^/\s]+)', word)
            if match:
                host = match.group(1).lower()
                if host not in TRUSTED_NPM_HOSTS and not host.endswith(".npmjs.org"):
                    return ("npm_url_install", f"npm install from non-registry source: {host}")

    for i, word in enumerate(words):
        if word == "--registry":
            if i + 1 < len(words):
                url = words[i + 1]
                match = re.search(r'https?://([^/\s]+)', url)
                if match:
                    host = match.group(1).lower()
                    if host not in TRUSTED_NPM_HOSTS and not host.endswith(".npmjs.org"):
                        return ("npm_url_install", f"npm using non-registry source: {host}")

    return None


def check_web3_rpc(command):
    if not any(ind in command for ind in ["/v1/", "/rpc", "/jsonrpc"]):
        return None

    command_lower = command.lower()
    for indicator in WEB3_INDICATORS:
        if indicator in command_lower:
            return ("web3_rpc_endpoint", f"Web3 RPC endpoint detected: {indicator}")

    return None


def check_web3_address(command):
    if re.search(r'0x[0-9a-fA-F]{40}', command):
        return ("web3_address_in_url", "Ethereum address detected in command")

    return None


def check_git_typosquat(command):
    words = command.split()
    if len(words) < 2:
        return None

    cmd = words[0].lower()
    if cmd != "git":
        return None

    if "clone" not in [w.lower() for w in words]:
        return None

    urls = re.findall(r'(?:https?://|git@)([^/\s:]+)[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?(?:\s|$)', command)
    for host, owner, repo in urls:
        host_lower = host.lower()
        if host_lower not in ("github.com", "gitlab.com", "bitbucket.org"):
            continue

        owner_lower = owner.lower()
        repo_lower = repo.lower().rstrip('.git')

        for pop_owner, pop_repo in POPULAR_REPOS:
            po = pop_owner.lower()
            pr = pop_repo.lower()

            if owner_lower == po and levenshtein(repo_lower, pr) == 1:
                return ("git_typosquat", f"Possible typosquat: {owner}/{repo} is 1 edit from {pop_owner}/{pop_repo}")
            if repo_lower == pr and levenshtein(owner_lower, po) == 1:
                return ("git_typosquat", f"Possible typosquat: {owner}/{repo} is 1 edit from {pop_owner}/{pop_repo}")

    return None
