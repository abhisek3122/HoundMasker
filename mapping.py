"""
mapping.py
----------
Persistent, file-backed mapping store.

Mapping file layout (mapping.json):
{
  "session_prefix": "xKtmPqRnJsWvBcLaFg",
  "counters": {
    "domain": 1, "user": 0, "computer": 0, "group": 0,
    "gpo": 0, "ou": 0, "ca": 0, "certtemplate": 0,
    "container": 0, "sidtriple": 0
  },
  "domains":      { "TRAINING.LOCAL": "xKt...-domain1" },
  "sid_triples":  { "1468306160-356025236-3522329279": "xKt...-domain1" },
  "users":        { "JSMITH": "xKt...-user1" },
  "computers":    { "WEB01": "xKt...-computer1" },
  "groups":       { "IT-ADMINS": "xKt...-group1" },
  "gpos":         { "IT SECURITY POLICY": "xKt...-gpo1" },
  "ous":          { "IT": "xKt...-ou1" },
  "cas":          { "CORP-CA": "xKt...-ca1" },
  "certtemplates": { "CUSTOMTEMPLATE": "xKt...-certtemplate1" },
  "containers":   { "CUSTOMCONTAINER": "xKt...-container1" }
}

Keys are stored UPPERCASE for case-insensitive lookup.
sid_triples map the A-B-C portion (without S-1-5-21- prefix) so that
all SIDs from the same domain resolve to the same masked triple.
The domain token and sid_triple token are kept in sync: domain1 <-> sidtriple1
so the mapping file is human-readable.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

from token_gen import generate_prefix, make_token, TYPE_SID_TRIPLE, gen_fake_sid_triple


# All bucket names (must match mapping.json layout)
BUCKETS = [
    "domains",
    "sid_triples",
    "users",
    "computers",
    "groups",
    "gpos",
    "ous",
    "cas",
    "certtemplates",
    "containers",
]

# Counter keys (one per token type)
COUNTER_KEYS = [
    "domain", "sidtriple", "user", "computer", "group",
    "gpo", "ou", "ca", "certtemplate", "container",
]


class MappingStore:
    """
    Holds the in-memory mapping table and syncs it to disk on every write.
    """

    def __init__(self, mapping_path: Path):
        self.path = mapping_path
        self._data: dict = {}
        self._dirty = False

    # ------------------------------------------------------------------
    # Initialisation helpers (called by main.py, not by the store itself)
    # ------------------------------------------------------------------

    def init_new(self) -> None:
        """Create a brand-new mapping.  Caller must ensure file doesn't exist."""
        prefix = generate_prefix()
        self._data = {
            "session_prefix": prefix,
            "counters": {k: 0 for k in COUNTER_KEYS},
        }
        for bucket in BUCKETS:
            self._data[bucket] = {}
        self._flush()
        print(f"[+] New mapping initialised  →  {self.path}")
        print(f"    Session prefix: {prefix}")

    def load_existing(self) -> None:
        """Load an existing mapping from disk.  Raises on corrupt file."""
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                self._data = json.load(fh)
        except json.JSONDecodeError as exc:
            sys.exit(f"[!] Mapping file is corrupt: {exc}")

        # Sanity-check required keys
        for required in ("session_prefix", "counters"):
            if required not in self._data:
                sys.exit(
                    f"[!] Mapping file is missing required key '{required}'. "
                    "File may be from an incompatible version."
                )
        for bucket in BUCKETS:
            if bucket not in self._data:
                self._data[bucket] = {}   # forward-compat: add missing buckets
        print(f"[+] Loaded existing mapping  →  {self.path}")
        print(f"    Session prefix : {self._data['session_prefix']}")
        self._print_stats()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def prefix(self) -> str:
        return self._data["session_prefix"]

    def get(self, bucket: str, original: str) -> Optional[str]:
        """Look up an already-mapped value (case-insensitive key)."""
        return self._data[bucket].get(original.upper())

    def register(self, bucket: str, original: str, type_name: str) -> str:
        """
        Return the masked token for *original* in *bucket*.
        If not yet mapped, create a new token, persist, and return it.
        Keys are normalised to UPPERCASE before storage.
        """
        key = original.upper()
        existing = self._data[bucket].get(key)
        if existing:
            return existing

        # Allocate a new counter for this type
        counter_key = type_name  # e.g. "domain", "user", ...
        self._data["counters"][counter_key] += 1
        counter = self._data["counters"][counter_key]
        token = make_token(self.prefix, type_name, counter)
        self._data[bucket][key] = token
        self._flush()
        return token

    def link_domain_triple(self, domain: str, triple: str) -> tuple[str, str]:
        """
        Authoritatively link a real domain NAME with its real SID triple.

        Unlike register_domain_and_triple (which is called with placeholder
        values when only one side is known), this is called when BOTH the real
        domain name and the real triple are known at once (e.g. from a Trust's
        TargetDomainName + TargetDomainSid, or a domain object's name + domainsid).

        It cleans up any placeholder entries (__DOMAIN__name__ in sid_triples,
        __TRIPLE__triple__ in domains) that a one-sided earlier call may have
        created, and collapses everything to a single consistent domain token +
        fake triple. This prevents unresolvable placeholder anomalies in
        mapping.json.

        Returns (domain_token, fake_triple).
        """
        domain_key = domain.upper()
        triple_key = triple.upper()

        placeholder_domain_key = f"__TRIPLE__{triple_key}__"   # lives in domains
        placeholder_triple_key = f"__DOMAIN__{domain_key}__"   # lives in sid_triples

        existing_domain = self._data["domains"].get(domain_key)
        existing_triple = self._data["sid_triples"].get(triple_key)
        ph_domain_token = self._data["domains"].get(placeholder_domain_key)
        ph_fake_triple  = self._data["sid_triples"].get(placeholder_triple_key)

        # Resolve the domain token: prefer a real one, else adopt a placeholder's
        domain_token = existing_domain or ph_domain_token
        # Resolve the fake triple: prefer a real one, else adopt a placeholder's
        fake_triple = existing_triple or ph_fake_triple

        if domain_token is None and fake_triple is None:
            # Nothing exists yet — allocate a fresh linked pair
            self._data["counters"]["domain"] += 1
            n = self._data["counters"]["domain"]
            domain_token = make_token(self.prefix, "domain", n)
            fake_triple  = gen_fake_sid_triple()
            self._data["counters"]["sidtriple"] = n
        elif domain_token is None:
            self._data["counters"]["domain"] += 1
            n = self._data["counters"]["domain"]
            domain_token = make_token(self.prefix, "domain", n)
            self._data["counters"]["sidtriple"] = n
        elif fake_triple is None:
            fake_triple = gen_fake_sid_triple()

        # Write the authoritative real-keyed entries
        self._data["domains"][domain_key]     = domain_token
        self._data["sid_triples"][triple_key] = fake_triple

        # Remove any placeholder entries now that we have real keys
        self._data["domains"].pop(placeholder_domain_key, None)
        self._data["sid_triples"].pop(placeholder_triple_key, None)

        self._flush()
        return domain_token, fake_triple

    def register_domain_and_triple(self, domain: str, triple: str) -> tuple[str, str]:
        """
        Register a domain name and its corresponding SID triple together,
        so both the domain token and the triple token share the same counter
        number (making the mapping file human-readable).

        Returns (domain_token, triple_token).
        """
        domain_key = domain.upper()
        triple_key = triple.upper()

        # Both may already exist
        existing_domain = self._data["domains"].get(domain_key)
        existing_triple = self._data["sid_triples"].get(triple_key)

        if existing_domain and existing_triple:
            return existing_domain, existing_triple

        if existing_domain and not existing_triple:
            # Domain token exists but we haven't seen its SID triple yet — generate one
            triple_token = gen_fake_sid_triple()
            self._data["sid_triples"][triple_key] = triple_token
            self._flush()
            return existing_domain, triple_token

        if existing_triple and not existing_domain:
            # Triple exists but no domain name token yet — allocate one
            self._data["counters"]["domain"] += 1
            n = self._data["counters"]["domain"]
            domain_token = make_token(self.prefix, "domain", n)
            self._data["domains"][domain_key] = domain_token
            self._data["counters"]["sidtriple"] = n
            self._flush()
            return domain_token, existing_triple

        # Neither exists — allocate together
        self._data["counters"]["domain"] += 1
        n = self._data["counters"]["domain"]
        domain_token = make_token(self.prefix, "domain", n)
        triple_token = gen_fake_sid_triple()   # numeric A-B-C, valid in SID context
        self._data["domains"][domain_key]     = domain_token
        self._data["sid_triples"][triple_key] = triple_token
        # sidtriple counter kept in sync
        self._data["counters"]["sidtriple"] = n
        self._flush()
        return domain_token, triple_token

    def finalize(self) -> dict:
        """
        Resolve leftover placeholder entries created during masking.

        During a run, a domain seen without its SID (or vice-versa) leaves a
        one-sided placeholder:
          - domains bucket:     __TRIPLE__<triple>__  -> domain_token
          - sid_triples bucket: __DOMAIN__<name>__    -> fake_triple

        By the end of a full run both real sides usually exist. This pass:
          1. For each __TRIPLE__<triple>__ in domains, if a real domain name
             maps to the same fake triple, drop the placeholder (the real
             domain token already covers it). Otherwise keep it but it stays a
             standalone unresolved triple (rare — a SID whose domain name never
             appeared anywhere in the dataset).
          2. For each __DOMAIN__<name>__ in sid_triples, if that domain name has
             a real entry in domains, ensure the real triple is linked and drop
             the placeholder.

        Returns a report dict: {"resolved": N, "unresolved": [...]}.
        """
        resolved = 0
        unresolved = []

        # Build reverse: fake_triple -> real domain name (from real sid_triples)
        real_triple_to_name = {}
        for key, fake in list(self._data["sid_triples"].items()):
            if not key.startswith("__"):
                # key is the REAL triple; find the domain name that pairs with it
                # by looking for a domains entry whose token counter matches — but
                # simpler: we don't need the name here, just that it's real.
                pass

        # Pass 1: __DOMAIN__<name>__ placeholders in sid_triples
        for key in list(self._data["sid_triples"].keys()):
            if key.startswith("__DOMAIN__"):
                name = key[len("__DOMAIN__"):-2]  # strip __DOMAIN__ and trailing __
                fake_triple = self._data["sid_triples"][key]
                # Does this domain name have a real entry with a real triple?
                if name.upper() in self._data["domains"]:
                    # Find whether a real triple already exists for this domain.
                    # If the placeholder's fake_triple isn't referenced by a real
                    # triple key, we simply drop the placeholder — the domain
                    # token in domains bucket is what unmask uses for names, and
                    # real SID triples are keyed by their real value elsewhere.
                    del self._data["sid_triples"][key]
                    resolved += 1
                else:
                    unresolved.append(f"sid_triples:{key}")

        # Pass 2: __TRIPLE__<triple>__ placeholders in domains
        for key in list(self._data["domains"].keys()):
            if key.startswith("__TRIPLE__"):
                triple = key[len("__TRIPLE__"):-2]
                # If this real triple exists in sid_triples, the fake triple is
                # already recorded there; the placeholder domain token is
                # redundant with whatever real domain owns this triple.
                if triple in self._data["sid_triples"]:
                    del self._data["domains"][key]
                    resolved += 1
                else:
                    unresolved.append(f"domains:{key}")

        if resolved or unresolved:
            self._flush()

        return {"resolved": resolved, "unresolved": unresolved}

    def summary(self) -> dict:
        """Return count of mapped items per bucket."""
        return {b: len(self._data[b]) for b in BUCKETS}

    def iter_bucket(self, bucket: str):
        """
        Iterate over (original_uppercase_key, masked_token) pairs in a bucket.
        Used by masker to do literal string replacement of known org names
        in free-text fields (e.g. CA names embedded in URL path segments).
        """
        return self._data.get(bucket, {}).items()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        """Write the full mapping to disk atomically (write-then-rename)."""
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, ensure_ascii=False)
        tmp.replace(self.path)

    def _print_stats(self) -> None:
        for bucket, count in self.summary().items():
            if count:
                print(f"    {bucket:<14}: {count} entries")


if __name__ == "__main__":
    import sys
    print(
        f"This is a library module. Run the tool with:\n\n"
        "  python3 houndmasker.py --new  file1.json file2.json ...\n"
        "  python3 houndmasker.py --extend file1.json file2.json ...",
        file=sys.stderr
    )
    sys.exit(1)
