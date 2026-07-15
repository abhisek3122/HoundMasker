#!/usr/bin/env python3
"""
unmask.py
---------
Reverse-lookup and bulk text translation for houndmasker output.

Given a mapping.json, this tool answers two needs:

  1. SINGLE LOOKUP — resolve any token or original string in either direction.
       token     -> original  (the common case: reading AI analysis)
       original  -> token      (find what a real name was masked to)

  2. BULK TRANSLATION — paste a block of masked text (e.g. an LLM's analysis)
     and get every token substituted back to its real name in one pass.
     This is the main workflow: turn "xKtm-user47 has GenericAll on
     xKtm-group8" into "jsmith has GenericAll on IT-Admins".

Usage
-----
  # Single lookup (token or original, auto-detected direction)
  python3 unmask.py --mapping mapping.json  xKtm-group8
  python3 unmask.py --mapping mapping.json  "IT-Admins"

  # Bulk translation — pipe text in
  echo "xKtm-user47 owns xKtm-computer3" | python3 unmask.py --mapping mapping.json
  python3 unmask.py --mapping mapping.json < ai_analysis.txt

  # Translate a whole file
  python3 unmask.py --mapping mapping.json --file ai_analysis.txt

  # Interactive mode (no query args, no piped input)
  python3 unmask.py --mapping mapping.json

If --mapping is omitted, the tool looks for mapping.json in the current
directory, then in ./modified_files_* folders (newest first).

Direction detection
-------------------
A query containing the session prefix is treated as a token -> original lookup.
Anything else is tried as original -> token first, then as a token. Bulk
translation always goes token -> original (and reverses fake SID triples).
"""

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Mapping loading
# ---------------------------------------------------------------------------

BUCKETS = [
    "domains", "sid_triples", "users", "computers", "groups",
    "gpos", "ous", "cas", "certtemplates", "containers",
]

# Bucket -> human-readable type label
TYPE_LABEL = {
    "domains":       "Domain",
    "sid_triples":   "SID triple",
    "users":         "User",
    "computers":     "Computer",
    "groups":        "Group",
    "gpos":          "GPO",
    "ous":           "OU",
    "cas":           "CA",
    "certtemplates": "Cert Template",
    "containers":    "Container",
}


def find_mapping() -> Path:
    """Locate a mapping.json automatically if not given explicitly."""
    if Path("mapping.json").exists():
        return Path("mapping.json")
    # Look in modified_files_* dirs, newest first
    candidates = sorted(glob.glob("modified_files_*/mapping.json"), reverse=True)
    if candidates:
        return Path(candidates[0])
    sys.exit(
        "[!] No mapping.json found. Specify one with --mapping PATH.\n"
        "    Looked in: ./mapping.json and ./modified_files_*/mapping.json"
    )


class Unmasker:
    """Holds the mapping and provides lookup + translation."""

    def __init__(self, mapping_path: Path):
        with open(mapping_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.prefix = self.data.get("session_prefix", "")
        self.mapping_path = mapping_path

        # All lookups are CASE-INSENSITIVE.
        #   forward: ORIGINAL.lower()  -> (original_display, token, bucket)
        #   reverse: token.lower()     -> (original_display, token, bucket)
        # We keep the original display casing so output looks right, but every
        # key is lowercased so queries match regardless of how they were typed
        # or copied (AI output, shells, and editors all mangle case).
        self.forward: dict = {}
        self.reverse: dict = {}

        for bucket in BUCKETS:
            for original, token in self.data.get(bucket, {}).items():
                if original.startswith("__"):
                    # Internal placeholder — still index the token so SID
                    # triples and domain-prefixed SIDs reverse correctly.
                    self.reverse.setdefault(
                        token.lower(), (self._clean_placeholder(original), token, bucket)
                    )
                    continue
                # A name can exist in more than one bucket (e.g. "Administrator"
                # as a user and a container), so keep every entry, not just the
                # last — the forward map maps lower(name) -> list of matches.
                self.forward.setdefault(original.lower(), []).append(
                    (original, token, bucket)
                )
                self.reverse[token.lower()]    = (original, token, bucket)

        # Bulk-translation regex: matches any token, case-insensitively,
        # longest-first so the alternation prefers the most specific match.
        all_tokens = [
            entry[1] for entry in self.reverse.values()
            if entry[1] and not entry[1].startswith("__")
        ]
        if all_tokens:
            sorted_tokens = sorted(set(all_tokens), key=len, reverse=True)
            self._token_re = re.compile(
                "|".join(re.escape(t) for t in sorted_tokens),
                re.IGNORECASE,
            )
        else:
            self._token_re = None

    # ------------------------------------------------------------------
    # Single lookup
    # ------------------------------------------------------------------

    def lookup(self, query: str) -> list[str]:
        """
        Resolve a single query in whichever direction makes sense.
        Fully case-insensitive. Returns human-readable result lines.
        """
        results: list[str] = []
        q = query.strip()
        ql = q.lower()

        # 1 + 2. Gather every exact match, in both directions. A token resolves
        # to one original; a name may resolve to several (one per bucket), so
        # collect them all and show all — never silently pick one.
        matches: list[tuple[str, str, str, str]] = []
        if ql in self.reverse:
            original, token, bucket = self.reverse[ql]
            matches.append(("token", original, token, bucket))
        for original, token, bucket in self.forward.get(ql, []):
            matches.append(("name", original, token, bucket))

        if matches:
            def fmt(kind, original, token, bucket):
                label = TYPE_LABEL.get(bucket, bucket)
                if kind == "token":
                    return f"{token}  ->  [{label}] {original}"
                return f"[{label}] {original}  ->  {token}"

            if len(matches) == 1:
                results.append(fmt(*matches[0]))
            else:
                results.append(f"'{q}' — {len(matches)} matches:")
                results.extend(f"  {fmt(*m)}" for m in matches)
            return results

        # 3. A SID? Reverse the masked triple / domain prefix inside it.
        sid_result = self._lookup_sid(q)
        if sid_result:
            results.append(sid_result)
            return results

        # 4. Partial / substring match across both directions.
        partial = self._partial_matches(ql)
        if partial:
            results.append(f"No exact match for '{q}'. Partial matches:")
            results.extend(f"  {p}" for p in partial[:20])
            if len(partial) > 20:
                results.append(f"  ... and {len(partial) - 20} more")
            return results

        results.append(f"No match found for '{q}'.")
        return results

    def _lookup_sid(self, sid: str) -> str:
        """If the query is a SID, reverse the masked triple / domain prefix."""
        # Masked standard SID: S-1-5-21-<fake_triple>-RID
        m = re.match(r'^(S-1-5-21-)(\d+-\d+-\d+)((?:-\d+)*)$', sid, re.IGNORECASE)
        if m:
            fake_triple = m.group(2)
            for original, fake in self.data.get("sid_triples", {}).items():
                if fake == fake_triple and not original.startswith("__"):
                    return f"{sid}  ->  S-1-5-21-{original}{m.group(3)}"
            return None

        # Domain-prefixed SID: <token>-S-1-...   (case-insensitive token match)
        m = re.match(r'^(.+?)-(S-1-[0-9].*)$', sid, re.IGNORECASE)
        if m:
            token, body = m.group(1), m.group(2)
            entry = self.reverse.get(token.lower())
            if entry:
                original = entry[0]
                return f"{sid}  ->  {original}-{body}"
        return None

    def _partial_matches(self, ql: str) -> list[str]:
        """Find substring matches in both originals and tokens (case-insensitive)."""
        out = []
        seen = set()
        for key, entries in self.forward.items():
            if ql in key:
                for original, token, bucket in entries:
                    if token in seen:
                        continue
                    seen.add(token)
                    label = TYPE_LABEL.get(bucket, bucket)
                    out.append(f"[{label}] {original}  <->  {token}")
        return out

    @staticmethod
    def _clean_placeholder(placeholder: str) -> str:
        """Turn __DOMAIN__X__ or __TRIPLE__X__ into X."""
        m = re.match(r'^__\w+?__(.+)__$', placeholder)
        return m.group(1) if m else placeholder

    # ------------------------------------------------------------------
    # Bulk translation
    # ------------------------------------------------------------------

    def translate(self, text: str) -> str:
        """
        Replace every masked token in *text* with its original value.
        Case-insensitive: tokens match regardless of casing. Handles named
        tokens and fake SID triples.
        """
        if not text:
            return text

        result = text

        # 1. Replace named tokens (case-insensitive)
        if self._token_re:
            def repl(m: re.Match) -> str:
                entry = self.reverse.get(m.group(0).lower())
                return entry[0] if entry else m.group(0)
            result = self._token_re.sub(repl, result)

        # 2. Reverse fake SID triples inside any S-1-5-21-... SIDs
        triple_map = {
            fake: original
            for original, fake in self.data.get("sid_triples", {}).items()
            if not original.startswith("__")
        }
        if triple_map:
            def sid_repl(m: re.Match) -> str:
                original = triple_map.get(m.group(1))
                return f"S-1-5-21-{original}" if original else m.group(0)
            result = re.sub(r'S-1-5-21-(\d+-\d+-\d+)', sid_repl, result)

        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> str:
        lines = [f"Mapping: {self.mapping_path}", f"Session prefix: {self.prefix}", ""]
        for bucket in BUCKETS:
            count = len([k for k in self.data.get(bucket, {}) if not k.startswith("__")])
            if count:
                lines.append(f"  {TYPE_LABEL.get(bucket, bucket):14s}: {count}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def _run_block(unmasker: "Unmasker", lines: list[str]) -> None:
    """Look up a single identifier; translate anything else.

    A single line is a lookup when it's one bare token, or when it exactly
    matches a known name/token (so multi-word names like 'SENIOR MANAGEMENT'
    resolve too). Everything else — prose, multiple lines — is translated.
    """
    if not lines:
        return
    if len(lines) == 1:
        s = lines[0].strip()
        ql = s.lower()
        if not re.search(r"\s", s) or ql in unmasker.forward or ql in unmasker.reverse:
            for r in unmasker.lookup(s):
                print(r)
            return
    print(unmasker.translate("\n".join(lines)))


def interactive(unmasker: Unmasker) -> None:
    print("houndmasker unmask — interactive mode")
    print(unmasker.stats())
    print("\nEnter a token or name, then a blank line (press Enter twice) to run it.")
    print("To translate a block, paste it (any number of lines) and end with a blank line.")
    print("Commands (single Enter): :stats, :quit\n")

    buffer: list[str] = []
    while True:
        try:
            line = input("unmask> " if not buffer else "   ... ")
        except (EOFError, KeyboardInterrupt):
            print()
            if buffer:              # flush anything pending on Ctrl-D/Ctrl-C
                _run_block(unmasker, buffer)
            break

        if not buffer:
            # First line of a new entry: commands are handled on a single Enter.
            cmd = line.strip()
            if cmd in (":quit", ":q", "quit", "exit"):
                break
            if cmd == ":stats":
                print(unmasker.stats())
                continue
            if cmd == "":
                continue
            buffer.append(line)     # start accumulating; a blank line will run it
            continue

        # Already accumulating: a blank line runs the block, anything else extends it.
        if line.strip() == "":
            _run_block(unmasker, buffer)
            buffer = []
        else:
            buffer.append(line)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        prog="unmask",
        description="Reverse-lookup and bulk-translate houndmasker output.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 unmask.py --mapping mapping.json xKtm-group8
  python3 unmask.py --mapping mapping.json "IT-Admins"
  echo "xKtm-user47 owns xKtm-computer3" | python3 unmask.py --mapping mapping.json
  python3 unmask.py --mapping mapping.json --file ai_analysis.txt
  python3 unmask.py --mapping mapping.json          # interactive
        """,
    )
    p.add_argument("--mapping", metavar="PATH",
                   help="Path to mapping.json (auto-detected if omitted)")
    p.add_argument("--file", metavar="PATH",
                   help="Translate an entire text file (bulk mode)")
    p.add_argument("--stats", action="store_true",
                   help="Print mapping statistics and exit")
    p.add_argument("query", nargs="*",
                   help="Token or original string to look up (single lookup)")
    args = p.parse_args()

    mapping_path = Path(args.mapping) if args.mapping else find_mapping()
    if not mapping_path.exists():
        sys.exit(f"[!] Mapping file not found: {mapping_path}")

    unmasker = Unmasker(mapping_path)

    if args.stats:
        print(unmasker.stats())
        return

    # Mode 1: explicit file → bulk translate
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
        print(unmasker.translate(text))
        return

    # Mode 2: query args → single lookup (one per arg)
    if args.query:
        for q in args.query:
            for line in unmasker.lookup(q):
                print(line)
        return

    # Mode 3: piped stdin → bulk translate
    if not sys.stdin.isatty():
        text = sys.stdin.read()
        if text.strip():
            print(unmasker.translate(text))
            return

    # Mode 4: nothing supplied → interactive
    interactive(unmasker)


if __name__ == "__main__":
    main()
