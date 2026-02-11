SOURCE_COMMANDS = {
    "curl", "wget", "fetch", "scp", "rsync",
    "iwr", "irm", "invoke-webrequest", "invoke-restmethod"
}

INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh",
    "python", "python3", "node", "perl", "ruby", "php",
    "iex", "invoke-expression"
}

INSECURE_TLS_FLAGS = {"-k", "--insecure", "--no-check-certificate"}

URL_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "v.gd", "goo.gl", "ow.ly"
}

LOOKALIKE_TLDS = {"zip", "mov", "app", "dev", "run"}

TRUSTED_DOCKER_REGISTRIES = {
    "docker.io", "ghcr.io", "gcr.io", "quay.io",
    "registry.k8s.io", "mcr.microsoft.com", "public.ecr.aws"
}

TRUSTED_PIP_HOSTS = {"pypi.org", "files.pythonhosted.org"}

TRUSTED_NPM_HOSTS = {"registry.npmjs.org", "npmjs.com"}

WEB3_INDICATORS = {
    "infura.io", "alchemy.com", "moralis.io", "chainstack.com", "getblock.io"
}

PROXY_ENV_VARS = {
    "HTTP_PROXY", "http_proxy",
    "HTTPS_PROXY", "https_proxy",
    "ALL_PROXY", "all_proxy"
}

KNOWN_SENSITIVE_PATHS = {
    "install", "setup", "init", "config", "login", "auth",
    "admin", "api", "token", "key", "secret", "password"
}

POPULAR_REPOS = [
    ("torvalds", "linux"),
    ("microsoft", "vscode"),
    ("facebook", "react"),
    ("vuejs", "vue"),
    ("angular", "angular"),
    ("tensorflow", "tensorflow"),
    ("kubernetes", "kubernetes"),
    ("golang", "go"),
    ("rust-lang", "rust"),
    ("python", "cpython"),
    ("nodejs", "node"),
    ("docker", "docker-ce"),
    ("moby", "moby"),
    ("homebrew", "brew"),
    ("ohmyzsh", "ohmyzsh"),
    ("nvm-sh", "nvm"),
    ("git", "git"),
    ("apache", "httpd"),
    ("nginx", "nginx"),
    ("redis", "redis"),
    ("postgres", "postgres"),
    ("mysql", "mysql-server"),
    ("elastic", "elasticsearch"),
    ("grafana", "grafana"),
    ("prometheus", "prometheus"),
    ("hashicorp", "terraform"),
    ("hashicorp", "vault"),
    ("ansible", "ansible"),
    ("chef", "chef"),
    ("puppet", "puppet"),
]

HIDDEN_COMMAND_INDICATORS = [
    "curl ", "wget ", "bash", "/bin/", "sudo ", "rm ", "chmod ",
    "eval ", "exec ", "> /", ">> /", "| sh"
]

BIDI_CONTROL_CHARS = {
    '\u200e',  # LRM
    '\u200f',  # RLM
    '\u202a',  # LRE
    '\u202b',  # RLE
    '\u202c',  # PDF
    '\u202d',  # LRO
    '\u202e',  # RLO
    '\u2066',  # LRI
    '\u2067',  # RLI
    '\u2068',  # FSI
    '\u2069',  # PDI
}

ZERO_WIDTH_CHARS = {
    '\u200b',  # ZWSP
    '\u200c',  # ZWNJ
    '\u200d',  # ZWJ
    '\ufeff',  # BOM / ZWNBSP
}

ARCHIVE_COMMANDS = {"tar", "unzip", "7z"}
ARCHIVE_SENSITIVE_TARGETS = [
    "-C /", "-C ~/", "-C $HOME/",
    "-d /", "-d ~/", "-d $HOME/",
    "> ~/.", ">> ~/."
]

DOTFILE_OVERWRITE_PATTERNS = [
    "> ~/.", ">> ~/.",
    "> $HOME/.", ">> $HOME/."
]

CURL_UPLOAD_FLAGS = {
    "-d", "--data", "--data-binary", "--data-raw", "--data-urlencode",
    "-F", "--form",
    "-T", "--upload-file",
}

WGET_UPLOAD_FLAGS = {
    "--post-data", "--post-file",
}

INVALID_HOST_CHARS = {'%', '\\'}
UNICODE_DOTS = {'\uff0e', '\u3002', '\uff61'}
