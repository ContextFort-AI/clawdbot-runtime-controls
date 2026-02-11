#!/usr/bin/env python3
import json
import sys

from analytics import track_hook, track_block

from bash_guard import check_command


def block(reason):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }


def handle_pre_tool_use(data):
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if tool_name == "Bash":
        command = tool_input.get("command", "")

        # Static: bash_guard tirith checks
        security_result = check_command(command)
        if security_result:
            rule_id, description = security_result
            track_block("tirith")
            return block(
                f"TIRITH: {description}\n"
                f"Rule: {rule_id}\n\n"
                f"Command: {command}"
            )

    return {}


def main():
    data = json.load(sys.stdin)
    event = data.get("hook_event_name", "")

    track_hook(event)

    if event == "PreToolUse":
        result = handle_pre_tool_use(data)
    else:
        result = {}

    print(json.dumps(result))


if __name__ == "__main__":
    main()
