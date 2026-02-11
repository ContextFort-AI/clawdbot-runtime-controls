"""
Bash security checks organized by category.
"""

from .command_shape import (
    check_pipe_to_interpreter,
    check_dotfile_overwrite,
    check_archive_extract,
)
from .terminal import (
    check_terminal_injection,
    check_hidden_multiline,
)
from .transport import (
    check_insecure_tls_flags,
    check_shortened_url,
    check_plain_http_to_sink,
    check_schemeless_to_sink,
    check_curl_upload,
)
from .ecosystem import (
    check_docker_untrusted_registry,
    check_pip_url_install,
    check_npm_url_install,
    check_web3_rpc,
    check_web3_address,
    check_git_typosquat,
)
from .environment import (
    check_proxy_env_set,
)
from .path import (
    check_non_ascii_path,
    check_homoglyph_in_path,
    check_double_encoding,
)
from .hostname import (
    check_non_ascii_hostname,
    check_mixed_script_in_label,
    check_userinfo_trick,
    check_confusable_domain,
    check_invalid_host_chars,
    check_trailing_dot_whitespace,
    check_non_standard_port,
    check_lookalike_tld,
    check_punycode_domain,
    check_raw_ip_url,
)

# All checks in recommended order
COMMAND_SHAPE_CHECKS = [
    check_pipe_to_interpreter,
    check_dotfile_overwrite,
    check_archive_extract,
]

TERMINAL_CHECKS = [
    check_terminal_injection,
    check_hidden_multiline,
]

TRANSPORT_CHECKS = [
    check_insecure_tls_flags,
    check_shortened_url,
    check_plain_http_to_sink,
    check_schemeless_to_sink,
    check_curl_upload,
]

ECOSYSTEM_CHECKS = [
    check_docker_untrusted_registry,
    check_pip_url_install,
    check_npm_url_install,
    check_web3_rpc,
    check_web3_address,
    check_git_typosquat,
]

ENVIRONMENT_CHECKS = [
    check_proxy_env_set,
]

PATH_CHECKS = [
    check_non_ascii_path,
    check_homoglyph_in_path,
    check_double_encoding,
]

HOSTNAME_CHECKS = [
    check_non_ascii_hostname,
    check_mixed_script_in_label,
    check_userinfo_trick,
    check_confusable_domain,
    check_invalid_host_chars,
    check_trailing_dot_whitespace,
    check_non_standard_port,
    check_lookalike_tld,
    check_punycode_domain,
    check_raw_ip_url,
]

ALL_CHECKS = (
    COMMAND_SHAPE_CHECKS +
    TERMINAL_CHECKS +
    TRANSPORT_CHECKS +
    ECOSYSTEM_CHECKS +
    ENVIRONMENT_CHECKS +
    PATH_CHECKS +
    HOSTNAME_CHECKS
)
