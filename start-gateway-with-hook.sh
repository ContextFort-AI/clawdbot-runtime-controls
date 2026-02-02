SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_PATH="$SCRIPT_DIR/spawn-hook.js"

if [ ! -f "$HOOK_PATH" ]; then
    exit 1
fi

> "$SCRIPT_DIR/spawn-gate.log"
> "$SCRIPT_DIR/spawn-audit.jsonl"

NODE_OPTIONS="--require $HOOK_PATH" openclaw gateway