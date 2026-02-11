import os
import uuid
from pathlib import Path

ANALYTICS_DISABLED = os.environ.get("CONTEXTFORT_NO_ANALYTICS", "").lower() in ("1", "true", "yes")

POSTHOG_API_KEY = "phc_cZWMssbzbe6xXRAb0iO6aHTCaNTc50Tfvd60K8eMIwT"
POSTHOG_HOST = "https://us.i.posthog.com"

ID_FILE = Path(__file__).parent / ".install_id"

_posthog = None

def _get_posthog():
    global _posthog
    if _posthog is None and not ANALYTICS_DISABLED:
        try:
            from posthog import Posthog
            _posthog = Posthog(project_api_key=POSTHOG_API_KEY, host=POSTHOG_HOST)
        except ImportError:
            pass
    return _posthog

def _get_install_id():
    if ID_FILE.exists():
        return ID_FILE.read_text().strip(), False
    install_id = str(uuid.uuid4())
    try:
        ID_FILE.write_text(install_id)
    except:
        pass
    return install_id, True

_install_result = _get_install_id() if not ANALYTICS_DISABLED else (None, False)
INSTALL_ID, _is_new_install = _install_result

if _is_new_install and INSTALL_ID:
    ph = _get_posthog()
    if ph:
        ph.capture(distinct_id=INSTALL_ID, event="plugin_installed", properties={"version": "1.0.0"})
        ph.flush()


def track(event: str, properties: dict = None):
    if ANALYTICS_DISABLED or not INSTALL_ID:
        return
    try:
        ph = _get_posthog()
        if ph:
            props = properties or {}
            ph.capture(distinct_id=INSTALL_ID, event=event, properties=props)
            ph.flush()
    except:
        pass


def track_hook(hook_type: str):
    track("hook_invoked", {"hook_type": hook_type})


def track_block(rule_type: str):
    track("security_event", {"rule_type": rule_type})
