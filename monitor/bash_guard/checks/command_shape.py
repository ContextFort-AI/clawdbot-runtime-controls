from ..patterns import (
    SOURCE_COMMANDS,
    INTERPRETERS,
    ARCHIVE_COMMANDS,
    ARCHIVE_SENSITIVE_TARGETS,
    DOTFILE_OVERWRITE_PATTERNS,
)
from .utils import split_commands


def _check_pipe_to_interpreter_single(command):
    """Check a single command (no && or ;) for pipe to interpreter."""
    if "|" not in command:
        return None

    parts = command.split("|")
    for i, part in enumerate(parts[1:], 1):
        part_stripped = part.strip()
        words = part_stripped.split()
        if not words:
            continue

        cmd = words[0].lower().rsplit("/", 1)[-1]

        if cmd in INTERPRETERS:
            source_part = parts[i-1].strip().split()[0] if parts[i-1].strip() else "unknown"
            source_cmd = source_part.rsplit("/", 1)[-1].lower()

            if source_cmd == "curl":
                return ("curl_pipe_shell", f"curl output piped to {cmd}")
            elif source_cmd == "wget":
                return ("wget_pipe_shell", f"wget output piped to {cmd}")
            elif source_cmd in SOURCE_COMMANDS:
                return ("pipe_to_interpreter", f"{source_cmd} output piped to interpreter: {cmd}")
            else:
                return ("pipe_to_interpreter", f"Output piped to interpreter: {cmd}")

        if cmd in ("sudo", "env"):
            for word in words[1:]:
                word_lower = word.lower().rsplit("/", 1)[-1]
                if word_lower in INTERPRETERS:
                    return ("pipe_to_interpreter", f"Output piped to {cmd} {word_lower}")
                if not word.startswith("-") and "=" not in word:
                    break

    return None


def check_pipe_to_interpreter(command):
    """Check for pipe to interpreter, handling && and ; separators."""
    for subcmd in split_commands(command):
        result = _check_pipe_to_interpreter_single(subcmd)
        if result:
            return result
    return None


def check_dotfile_overwrite(command):
    if "> /dev/null" in command:
        return None

    for subcmd in split_commands(command):
        for pattern in DOTFILE_OVERWRITE_PATTERNS:
            if pattern in subcmd:
                return ("dotfile_overwrite", f"Redirect to dotfile detected: {pattern}")

    return None


def check_archive_extract(command):
    for subcmd in split_commands(command):
        words = subcmd.split()
        if not words:
            continue

        cmd = words[0].lower().rsplit("/", 1)[-1]
        if cmd not in ARCHIVE_COMMANDS:
            continue

        for target in ARCHIVE_SENSITIVE_TARGETS:
            if target in subcmd:
                return ("archive_extract", f"Archive extraction to sensitive path: {target}")

    return None
