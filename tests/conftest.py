"""Shared fixtures and synthetic credentials.

The fake secrets below satisfy each detector's regex *and* survive trufflehog's
false-positive filters, which reject placeholder terms ("example", "abcde", ...)
and dictionary words. None of them are real credentials.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from litellm_trufflehog import Scanner, fingerprint
from litellm_trufflehog._lib import NativeLibraryNotFound

# (?:AKIA|ABIA|ACCA)[A-Z0-9]{16}
AWS_KEY_ID = "AKIAQRSTUV234567WXYZ"
# [A-Za-z0-9+/]{40}, and must not look like a hex digest
AWS_SECRET = "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"
# (?:ghp|gho|...)_[a-zA-Z0-9_]{36,255}
GITHUB_PAT = "ghp_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5"
# sk-(?:...)T3BlbkFJ[A-Za-z0-9_-]+
OPENAI_KEY = "sk-Qm7Xk2Vp9Rt4T3BlbkFJLs6Wn3Zy8Hq5Jd7Fg2Kv4Mb"
# xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*
SLACK_TOKEN = "xoxb-1234567890123-1234567890123-Qm7Xk2Vp9Rt4Ls6Wn3Zy8Hq5"

# No issuer-identifying shape, as an internal service or a proxy hands out: found
# only by a catch-all detector, so only under the "paranoid" profile.
UNBRANDED_SECRET = "DlhsHVp-y4qvxL1-koFlber-pMeUMdB"
# The same, but 28 characters of the base64 alphabet. trufflehog's Generic detector
# discards anything that base64-decodes; ours is the one that catches this.
BASE64_SHAPED_SECRET = "1uFtpdS8i8mdY7kq6eetrrBEvOrM"
# For connection-string fixtures.
DB_PASSWORD = "iyHlOSsmrVRmHAfRpfPlmKHW"

CLEAN_TEXT = "What is the capital of France? Please answer briefly."

ALL_SECRETS = (AWS_KEY_ID, AWS_SECRET, GITHUB_PAT, OPENAI_KEY, SLACK_TOKEN)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "slow: slower end-to-end checks")


@pytest.fixture(scope="session")
def native_available() -> bool:
    try:
        Scanner(profile="minimal").close()
    except NativeLibraryNotFound as exc:
        pytest.skip(f"native library not built: {exc}")
    return True


@pytest.fixture(scope="session")
def scanner(native_available: bool) -> Iterator[Scanner]:
    """Session-scoped scanner: construction is the expensive part."""
    s = Scanner(profile="core")
    yield s
    s.close()


@pytest.fixture(scope="session")
def minimal_scanner(native_available: bool) -> Iterator[Scanner]:
    s = Scanner(profile="minimal")
    yield s
    s.close()


def assert_no_secrets(text: str) -> None:
    """Fail if any known fake secret survives in text."""
    for secret in ALL_SECRETS:
        assert secret not in text, f"secret {secret[:12]}... leaked into output"


def redaction(detector: str, secret: str) -> str:
    """The exact placeholder that redaction writes over ``secret``."""
    return f"[REDACTED:{detector}:{fingerprint(secret)}]"
