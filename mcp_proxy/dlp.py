import re
from typing import Any, Tuple, List, Dict, Union, Pattern, Optional


class DLPRedactor:
    """
    Data Loss Prevention engine.
    Scans child MCP server tool results and redacts credentials, API keys,
    JWTs, and private keys before returning results to client.
    """
    REDACTION_TAG = "[REDACTED_BY_GATEWAY]"

    PATTERNS: List[Tuple[str, Pattern]] = [
        # AWS Access Key ID
        ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        # AWS Secret Access Key
        ("AWS_SECRET", re.compile(r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?")),
        # GitHub Personal Access Tokens (Classic & Fine-grained)
        ("GITHUB_PAT", re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b")),
        # JSON Web Tokens (JWT)
        ("JWT", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\b")),
        # Private Keys (RSA, EC, DSA, OpenSSH)
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----")),
        # Generic API Keys / Bearer Tokens
        ("API_KEY", re.compile(r"(?i)\b(?:sk-[a-zA-Z0-9]{20,}|xox[baprs]-[0-9a-zA-Z]{10,})\b")),
    ]

    def __init__(self, custom_patterns: Optional[List[Tuple[str, Pattern]]] = None):
        self.rules = list(self.PATTERNS)
        if custom_patterns:
            self.rules.extend(custom_patterns)

    def redact_text(self, text: str) -> Tuple[str, int]:
        """Redacts sensitive strings from a text payload. Returns (redacted_text, count)."""
        if not text or not isinstance(text, str):
            return text, 0

        total_redactions = 0
        result = text
        for name, pattern in self.rules:
            if pattern.groups > 0:
                def replacer(match: re.Match) -> str:
                    nonlocal total_redactions
                    total_redactions += 1
                    matched_str = match.group(0)
                    for g in match.groups():
                        if g:
                            matched_str = matched_str.replace(g, self.REDACTION_TAG)
                    return matched_str
                result = pattern.sub(replacer, result)
            else:
                matches = pattern.findall(result)
                if matches:
                    total_redactions += len(matches)
                    result = pattern.sub(self.REDACTION_TAG, result)

        return result, total_redactions

    def redact_structure(self, data: Any) -> Tuple[Any, int]:
        """Recursively traverses and redacts dicts, lists, and primitives."""
        if isinstance(data, str):
            return self.redact_text(data)
        elif isinstance(data, list):
            count = 0
            new_list = []
            for item in data:
                r_item, c = self.redact_structure(item)
                new_list.append(r_item)
                count += c
            return new_list, count
        elif isinstance(data, dict):
            count = 0
            new_dict = {}
            for k, v in data.items():
                r_val, c = self.redact_structure(v)
                new_dict[k] = r_val
                count += c
            return new_dict, count
        else:
            return data, 0
