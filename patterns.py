# patterns.py

import re

# Verbose combined regex for secrets / credentials
# We keep it in one place so secret_scanner.py stays clean.
PATTERN_SOURCE = r"""
(
    # ───────────────── Existing patterns ─────────────────

    # DB / service connection strings
    (?:mongodb|postgres|mysql|jdbc|redis|ftp|smtp)[\s_\-=:][A-Za-z0-9+=._-]{10,}|

    # Azure storage-style keys
    Azure_Storage_(?:AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken)[^\n]+|

    # ClientSecret in config-style XML/JSON
    ClientSecret"\svalue=.+|

    # Generic access keys
    (?:AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)=\S{10,}|
    AccountKey=\S{10,}|

    # Rails-style secret key base
    secret_key_base:\s.[A-Za-z0-9_.-]{12,}|

    # Generic "secret" assignments
    secret(?:\s|:|=).+[A-Za-z0-9_.-]{12,}|

    # Bearer tokens
    Bearer\s.\S{11,}|

    # api-key/api_token style patterns
    api[_-](?:key|token)(?::|=).[A-Za-z0-9_.-]{10,}|

    # SSH public key
    ssh-rsa\s+[A-Za-z0-9+/=]+|

    # Private key headers
    -----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----|

    # Password-like patterns
    (?:password|passwd|pwd|Password|PASSWORD)\s*[:=]\s*["']?[^\s"']{8,}|

    # JWT tokens (very rough match)
    eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|


    # ───────────────── AWS-specific patterns ─────────────────

    # AWS Access Key ID in common variable names
    (?:AWS|aws)_?(?:ACCESS_KEY_ID|ACCESS_KEY|ACCESSKEY)\s*[:=]\s*["']?(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}["']?|

    # Standalone AWS Access Key ID (e.g. in logs or config)
    (?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}|

    # AWS Secret Access Key in variable-style usage
    (?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?|

    # Generic aws_*key style (slightly looser, may give some FPs)
    aws_?(?:secret|access)?_?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{16,}["']?|


    # ───────────────── OpenAI-specific patterns ─────────────────

    # OpenAI API key in env/var style
    (?:OPENAI_API_KEY|openai_api_key)\s*[:=]\s*["']?sk-[A-Za-z0-9]{20,}["']?|

    # Standalone OpenAI key pattern (sk-...)
    sk-[A-Za-z0-9]{20,}
)
"""


def build_pattern() -> re.Pattern:
    """
    Build the compiled regex pattern for secret detection.

    Keeping this in a separate module keeps the scanner logic clean and
    makes it easy to tweak patterns without touching core code.
    """
    return re.compile(PATTERN_SOURCE, re.IGNORECASE | re.VERBOSE)

