"""
token_gen.py
------------
Generates opaque masked tokens.

Two token formats:

1. Named tokens  (domain names, usernames, hostnames, group names, etc.)
   Format:  <18-char-random-prefix>-<type><counter>
   Example: xKtmPqRnJsWvBcLaFg-user1

   The prefix is purely alphabetic (no digits) so tokens can never be
   confused with real AD identifiers which always contain digits or dots.

2. Numeric SID triples  (the A-B-C domain component of a Windows SID)
   Format:  <uint32>-<uint32>-<uint32>
   Example: 2847193021-109847291-3829102847

   BloodHound CE's ingestor parses SIDs strictly — S-1-5-21-A-B-C-RID
   requires A, B, C to be decimal integers.  Alphabetic tokens in that
   position cause silent ingest failures and broken graph edges.
   Numeric fake triples are cryptographically random and unique per domain.
"""

import random
import secrets
import string

# Token type labels
TYPE_DOMAIN      = "domain"
TYPE_USER        = "user"
TYPE_COMPUTER    = "computer"
TYPE_GROUP       = "group"
TYPE_GPO         = "gpo"
TYPE_OU          = "ou"
TYPE_CA          = "ca"
TYPE_CERTTEMPLATE = "certtemplate"
TYPE_CONTAINER   = "container"
TYPE_SID_TRIPLE  = "sidtriple"   # only used as a bucket label, not in token string


def generate_prefix(length: int = 18) -> str:
    """
    Generate a random mixed-case alphabetic prefix.
    Purely alphabetic — no digits, no special characters — so the resulting
    tokens can never be confused with real AD identifiers (which always
    contain digits, dots, or hyphens).
    """
    return "".join(random.choices(string.ascii_letters, k=length))


def make_token(prefix: str, type_name: str, counter: int) -> str:
    """
    Build a named token from the session prefix, type label, and counter.

    >>> make_token("xKtmPqRnJsWvBcLaFg", "user", 3)
    'xKtmPqRnJsWvBcLaFg-user3'
    """
    return f"{prefix}-{type_name}{counter}"


def gen_fake_sid_triple() -> str:
    """
    Generate a cryptographically random numeric SID domain triple of the form:
        <A>-<B>-<C>
    where A, B, C are random 32-bit unsigned integers (range 1 – 4294967294).

    This triple is used to replace the real A-B-C domain portion inside
    Windows SIDs (S-1-5-21-A-B-C-RID), producing syntactically valid SIDs
    like S-1-5-21-2847193021-109847291-3829102847-512 that BloodHound CE
    parses and ingests correctly.

    Uses secrets.randbelow for unpredictability — the real domain triple
    must not be guessable from the fake one.
    """
    a = secrets.randbelow(0xFFFFFFFE) + 1  # 1 … 4294967294
    b = secrets.randbelow(0xFFFFFFFE) + 1
    c = secrets.randbelow(0xFFFFFFFE) + 1
    return f"{a}-{b}-{c}"


if __name__ == "__main__":
    import sys
    print(
        f"This is a library module. Run the tool with:\n\n"
        "  python3 houndmasker.py --new  file1.json file2.json ...\n"
        "  python3 houndmasker.py --extend file1.json file2.json ...",
        file=sys.stderr
    )
    sys.exit(1)
