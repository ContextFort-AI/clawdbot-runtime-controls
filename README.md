# AntiVirus for ClawdBot: Prompt Injection Prevention

Runtime controls for OpenClaw that intercepts child_process calls, enforces approval for external commands via Telegram, and detects prompt injection in command outputs.



https://github.com/user-attachments/assets/93064c17-9644-403b-8328-1da8014dae89




The runtime control live on Telegram.

## Usage

```bash
./start-gateway-with-hook.sh
```

## Requirements

- `~/.claude/hooks/.env` with `ANTHROPIC_API_KEY=sk-ant-...`
- Telegram channel configured in OpenClaw

## How It Works

1. Hooks Node.js `child_process` module at startup
2. Every spawn/exec call is intercepted before execution
3. Read-only commands pass through immediately
4. External/write commands require human approval on Telegram
5. Command outputs are checked for prompt injection
6. If injection detected, next external command is blocked with warning

## Code References

| What | Line |
|------|------|
| Command categories | `spawn-hook.js:104-108` |
| Notion read-only detection | `spawn-hook.js:117-122` |
| GitHub CLI read-only detection | `spawn-hook.js:124-130` |
| Notion content extraction | `spawn-hook.js:141-156` |
| Claude injection check | `spawn-hook.js:168-195` |
| Main intercept logic | `spawn-hook.js:230-280` |

## Command Categories

**SKIP_USER_CONFIRMATION** (line 106) - Read-only, no external writes:
- System info: `whoami`, `pwd`, `hostname`, `uname`, `sw_vers`
- File reads: `ls`, `cat`, `head`, `tail`, `file`, `wc`
- Network info: `arp`, `ifconfig`, `networksetup`, `scutil`
- Notion/GitHub: GET requests, search queries, list/view subcommands

**SKIP_RESPONSE_CHECK** (line 105) - Output cannot be attacker-influenced:
- `whoami`, `pwd`, `echo`, `hostname`, `uname`

**INTERNAL_COMMANDS** (line 107) - Always pass through, even with injection warning:
- All local system commands that don't touch external services

## Debug Mode

```bash
SPAWN_GATE_DEBUG=1 ./start-gateway-with-hook.sh
```

Logs to `spawn-gate.log`, audit trail in `spawn-audit.jsonl`.
