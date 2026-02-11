from ..patterns import (
    BIDI_CONTROL_CHARS,
    ZERO_WIDTH_CHARS,
    HIDDEN_COMMAND_INDICATORS,
)


def check_terminal_injection(command):
    if '\x1b[' in command or '\x1b]' in command or '\x1b_' in command or '\x1bP' in command:
        return ("ansi_escapes", "ANSI escape sequences detected")

    for char in command:
        code = ord(char)
        if code < 0x20 and char not in ('\n', '\t', '\x1b'):
            return ("control_chars", f"Control character detected: 0x{code:02x}")
        if code == 0x7f:
            return ("control_chars", "DEL control character detected")

    for char in command:
        if char in BIDI_CONTROL_CHARS:
            return ("bidi_controls", f"Bidirectional control character: U+{ord(char):04X}")

    for char in command:
        if char in ZERO_WIDTH_CHARS:
            return ("zero_width_chars", f"Zero-width character: U+{ord(char):04X}")

    return None


def check_hidden_multiline(command):
    lines = command.split('\n')
    if len(lines) <= 1:
        return None

    for i, line in enumerate(lines[1:], 1):
        trimmed = line.strip()
        if not trimmed:
            continue

        for indicator in HIDDEN_COMMAND_INDICATORS:
            if indicator in trimmed:
                return ("hidden_multiline", f"Hidden command on line {i+1}: {trimmed[:60]}")

    return None
