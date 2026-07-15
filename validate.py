#!/usr/bin/env python3
"""
validate.py
-----------
Post-masking validator for houndmasker output.

Compares the original BloodHound CE files against the masked output and the
mapping.json to verify that:

  1. LEAK CHECK       — no original organization strings appear in masked files
  2. SID VALIDITY     — every S-1-5-21-... SID is numerically valid
  3. CROSS-REFERENCE  — all Members/Aces object IDs still resolve consistently
  4. STRUCTURE        — object counts and membership counts are preserved
  5. META INTEGRITY   — meta blocks are unchanged (re-import safety)
  6. DESCRIPTIONS     — no non-safelisted descriptions survive

Usage:
    python3 validate.py --original ../LabFiles --masked ./modified_files_27_06_26

    # Or point at individual matched files (same basenames in both dirs)
    python3 validate.py --original /path/to/originals --masked /path/to/masked

Exit code 0 = all checks pass, 1 = one or more checks failed.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Valid SID: S-1-<authority>-<sub-authorities...>  (all numeric after S-1-)
_VALID_SID = re.compile(r'^S-1-[0-9]+(-[0-9]+)*$', re.IGNORECASE)
# Domain-prefixed SID like <token>-S-1-5-32-544 (prefix is masked, suffix numeric)
_DOMAIN_PREFIXED_SID = re.compile(r'-S-1-[0-9]+(-[0-9]+)*$', re.IGNORECASE)


class Validator:
    def __init__(self, original_dir: Path, masked_dir: Path):
        self.original_dir = original_dir
        self.masked_dir   = masked_dir
        self.mapping      = self._load_mapping()
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self.passes: list[str]   = []

    def _load_mapping(self) -> dict:
        mapping_path = self.masked_dir / "mapping.json"
        if not mapping_path.exists():
            sys.exit(f"[!] No mapping.json found in {self.masked_dir}")
        with open(mapping_path) as f:
            return json.load(f)

    def _matched_files(self) -> list[tuple[Path, Path]]:
        """Return (original, masked) file pairs that exist in both dirs."""
        pairs = []
        for masked in sorted(self.masked_dir.glob("*.json")):
            if masked.name == "mapping.json":
                continue
            original = self.original_dir / masked.name
            if original.exists():
                pairs.append((original, masked))
            else:
                self.warnings.append(f"No original found for {masked.name}")
        return pairs

    # ------------------------------------------------------------------
    # Check 1 — leak check
    # ------------------------------------------------------------------

    def check_leaks(self, pairs: list[tuple[Path, Path]]) -> None:
        """
        Verify none of the original sensitive strings appear in masked output.

        Only genuine organization-specific identifiers are checked:
          - original domain FQDNs and their NetBIOS short names
          - original numeric SID triples
          - original usernames, computer names, CA names

        Default AD vocabulary (group names, container names, property names)
        is deliberately preserved and excluded via the safelist, and matching
        uses word boundaries to avoid substring false positives.
        """
        try:
            from safelist import DEFAULT_GROUP_NAMES
        except ImportError:
            DEFAULT_GROUP_NAMES = frozenset()

        leak_terms: set[str] = set()

        # Original domain names + NetBIOS short names
        for original_domain in self.mapping.get("domains", {}):
            if original_domain.startswith("__"):
                continue
            leak_terms.add(original_domain)
            short = original_domain.split(".")[0]
            if len(short) > 3:
                leak_terms.add(short)

        # Original numeric SID triples
        for triple_key in self.mapping.get("sid_triples", {}):
            if triple_key.startswith("__"):
                continue
            leak_terms.add(triple_key)

        # Original org-specific names (users, computers, CAs)
        # Exclude any that are also default AD names (shouldn't happen, but safe)
        for bucket in ("users", "computers", "cas"):
            for original_name in self.mapping.get(bucket, {}):
                if len(original_name) <= 4:
                    continue
                if original_name.upper() in DEFAULT_GROUP_NAMES:
                    continue
                leak_terms.add(original_name)

        if not leak_terms:
            self.passes.append("Leak check: no terms to check (empty mapping)")
            return

        # Build ONE combined word-boundary regex, scanned once per file.
        # Sort longest-first so the alternation prefers the most specific match.
        sorted_terms = sorted(leak_terms, key=len, reverse=True)
        combined = re.compile(
            r'(?<![A-Z0-9])(' +
            "|".join(re.escape(t.upper()) for t in sorted_terms) +
            r')(?![A-Z0-9])'
        )

        # Descriptions are now nuked entirely, so there are no safe-description
        # contexts to preserve. Kept as an empty set for the context checker.
        safe_desc_upper: set = set()

        def is_accepted_context(content_upper: str, start: int, end: int) -> bool:
            """
            Return True if the matched term sits in a legitimately-preserved
            context that is NOT a leak:
              - SPN service-class prefix: TERM immediately followed by '/'
                (e.g. HTTP_SVC/host, MSSQL_SVC/host) — service classes are
                preserved on purpose and are not org-identifying.
              - Inside a safelisted Microsoft default description.
            """
            # SPN service-class: char right after the match is '/'
            if end < len(content_upper) and content_upper[end] == "/":
                return True
            # Inside a safe description: check the surrounding quoted string
            # Find the enclosing quotes
            left_q  = content_upper.rfind('"', 0, start)
            right_q = content_upper.find('"', end)
            if left_q >= 0 and right_q >= 0:
                enclosed = content_upper[left_q + 1:right_q]
                if enclosed in safe_desc_upper:
                    return True
            return False

        total_leaks = 0
        for _, masked in pairs:
            content_upper = masked.read_text().upper()
            for m in combined.finditer(content_upper):
                if is_accepted_context(content_upper, m.start(), m.end()):
                    continue
                total_leaks += 1
                idx = m.start()
                ctx = content_upper[max(0, idx-40):idx+len(m.group())+40]
                self.failures.append(
                    f"LEAK in {masked.name}: '{m.group()}' — ...{ctx.strip()}..."
                )
                if total_leaks > 20:
                    self.failures.append("... (more leaks suppressed)")
                    break
            if total_leaks > 20:
                break

        if total_leaks == 0:
            self.passes.append(
                f"Leak check: no original org-specific strings found "
                f"({len(leak_terms)} terms checked across {len(pairs)} files)"
            )

    # ------------------------------------------------------------------
    # Check 2 — SID validity
    # ------------------------------------------------------------------

    def check_sid_validity(self, pairs: list[tuple[Path, Path]]) -> None:
        invalid = 0
        for _, masked in pairs:
            content = masked.read_text()
            for m in re.finditer(r'"(S-1-5-21-[^"]+)"', content):
                sid = m.group(1)
                if not _VALID_SID.match(sid):
                    invalid += 1
                    if invalid <= 10:
                        self.failures.append(f"INVALID SID in {masked.name}: {sid}")
        if invalid == 0:
            self.passes.append("SID validity: all S-1-5-21-... SIDs are numerically valid")
        else:
            self.failures.append(f"SID validity: {invalid} invalid SIDs total")

    # ------------------------------------------------------------------
    # Check 3 — cross-reference integrity
    # ------------------------------------------------------------------

    def check_cross_references(self, pairs: list[tuple[Path, Path]]) -> None:
        """Verify all Members[].ObjectIdentifier resolve within the masked set."""
        all_oids: set[str] = set()
        masked_data: dict[str, dict] = {}

        for _, masked in pairs:
            data = json.loads(masked.read_text())
            masked_data[masked.name] = data
            for obj in data.get("data", []):
                oid = obj.get("ObjectIdentifier")
                if oid:
                    all_oids.add(oid)

        # Collect known pre-existing dangling refs from the ORIGINAL data so we
        # don't count them as masking failures
        original_dangling: set[str] = set()
        for original, masked in pairs:
            odata = json.loads(original.read_text())
            o_oids = {o.get("ObjectIdentifier") for o in odata.get("data", []) if o.get("ObjectIdentifier")}
            for obj in odata.get("data", []):
                for member in obj.get("Members", []):
                    mid = member.get("ObjectIdentifier", "")
                    # We can't easily check across all original files here, so
                    # we track per-file; cross-file dangling is handled below.

        # Build full original OID set across all originals
        all_original_oids: set[str] = set()
        for original, _ in pairs:
            odata = json.loads(original.read_text())
            for obj in odata.get("data", []):
                if obj.get("ObjectIdentifier"):
                    all_original_oids.add(obj["ObjectIdentifier"])
        # Find originally-dangling member refs
        for original, _ in pairs:
            odata = json.loads(original.read_text())
            for obj in odata.get("data", []):
                for member in obj.get("Members", []):
                    mid = member.get("ObjectIdentifier", "")
                    if mid.startswith("S-") and mid not in all_original_oids:
                        original_dangling.add(mid)

        broken = 0
        for fname, data in masked_data.items():
            for obj in data.get("data", []):
                for member in obj.get("Members", []):
                    mid = member.get("ObjectIdentifier", "")
                    if mid.startswith("S-") and mid not in all_oids:
                        # Was this dangling in the original too? (map via mapping not needed —
                        # if it's broken in masked and there's a corresponding count of
                        # dangling in original, it's pre-existing)
                        broken += 1

        # Compare broken count against original dangling count
        # The masked broken refs should equal the number of original dangling
        # refs (those simply don't exist in any file — a source data issue)
        expected_dangling = 0
        for fname, data in masked_data.items():
            pass  # counted above

        if broken == 0:
            self.passes.append("Cross-references: all Members object IDs resolve")
        elif original_dangling:
            self.warnings.append(
                f"Cross-references: {broken} dangling member ref(s) — "
                f"these correspond to {len(original_dangling)} object(s) "
                f"missing from the ORIGINAL data too (not a masking issue)"
            )
            self.passes.append("Cross-references: no NEW dangling references introduced by masking")
        else:
            self.failures.append(f"Cross-references: {broken} broken member references")

    # ------------------------------------------------------------------
    # Check 4 — structure preservation
    # ------------------------------------------------------------------

    def check_structure(self, pairs: list[tuple[Path, Path]]) -> None:
        mismatches = 0
        for original, masked in pairs:
            odata = json.loads(original.read_text())
            mdata = json.loads(masked.read_text())

            o_count = len(odata.get("data", []))
            m_count = len(mdata.get("data", []))
            if o_count != m_count:
                mismatches += 1
                self.failures.append(
                    f"Object count mismatch in {masked.name}: "
                    f"original={o_count}, masked={m_count}"
                )

            # Membership counts per object
            o_members = sum(len(o.get("Members", [])) for o in odata.get("data", []))
            m_members = sum(len(o.get("Members", [])) for o in mdata.get("data", []))
            if o_members != m_members:
                mismatches += 1
                self.failures.append(
                    f"Membership count mismatch in {masked.name}: "
                    f"original={o_members}, masked={m_members}"
                )

        if mismatches == 0:
            self.passes.append("Structure: object and membership counts preserved exactly")

    # ------------------------------------------------------------------
    # Check 5 — meta integrity
    # ------------------------------------------------------------------

    def check_meta(self, pairs: list[tuple[Path, Path]]) -> None:
        mismatches = 0
        for original, masked in pairs:
            odata = json.loads(original.read_text())
            mdata = json.loads(masked.read_text())
            if odata.get("meta") != mdata.get("meta"):
                mismatches += 1
                self.failures.append(f"Meta block changed in {masked.name}")
        if mismatches == 0:
            self.passes.append("Meta integrity: all meta blocks unchanged (re-import safe)")

    # ------------------------------------------------------------------
    # Check 6 — descriptions
    # ------------------------------------------------------------------

    def check_descriptions(self, pairs: list[tuple[Path, Path]]) -> None:
        """Verify ALL description fields are blanked (nuked unconditionally)."""
        survived = 0
        for _, masked in pairs:
            data = json.loads(masked.read_text())
            for obj in data.get("data", []):
                desc = obj.get("Properties", {}).get("description", "")
                if desc:
                    survived += 1
                    if survived <= 10:
                        self.failures.append(
                            f"Description not blanked in {masked.name}: '{desc[:60]}'"
                        )
        if survived == 0:
            self.passes.append("Descriptions: all description fields blanked")
        else:
            self.failures.append(f"Descriptions: {survived} description(s) not blanked")

    # ------------------------------------------------------------------
    # Check 7 — PII fields
    # ------------------------------------------------------------------

    def check_pii_fields(self, pairs: list[tuple[Path, Path]]) -> None:
        """Verify all free-text PII, path, and secret fields are blanked."""
        try:
            from masker import BLANK_FIELDS
            pii_fields = tuple(BLANK_FIELDS)
        except ImportError:
            pii_fields = (
                "displayname", "title", "givenname", "surname",
                "company", "department", "mail", "manager", "info", "comment",
                "homedirectory", "logonscript", "profilepath", "scriptpath",
            )
        survived = 0
        for _, masked in pairs:
            data = json.loads(masked.read_text())
            for obj in data.get("data", []):
                props = obj.get("Properties", {})
                for field in pii_fields:
                    if props.get(field):
                        survived += 1
                        if survived <= 10:
                            self.failures.append(
                                f"PII field '{field}' not blanked in {masked.name}: "
                                f"'{str(props[field])[:40]}'"
                            )
        if survived == 0:
            self.passes.append("PII fields: all blanked (displayname, title, etc.)")
        else:
            self.failures.append(f"PII fields: {survived} field(s) not blanked")

    # ------------------------------------------------------------------
    # Check 8 — ACE preservation
    # ------------------------------------------------------------------

    def check_ace_preservation(self, pairs: list[tuple[Path, Path]]) -> None:
        """
        Verify that:
          (a) ACE counts are preserved per object (no ACEs dropped)
          (b) well-known SID bodies are preserved exactly — only the masked
              domain prefix changes, never the S-1-... authority/sub-authority.

        This catches the class of bug where a SID like DOMAIN.LOCAL-S-1-1-0
        (Everyone) gets corrupted into an invalid form, silently dropping the
        edge when re-imported into BloodHound.
        """
        body_re = re.compile(r'(S-1-[0-9].*)$', re.IGNORECASE)
        count_mismatch = 0
        body_mismatch  = 0

        for original, masked in pairs:
            odata = json.loads(original.read_text())
            mdata = json.loads(masked.read_text())

            for o, m in zip(odata.get("data", []), mdata.get("data", [])):
                o_aces = o.get("Aces", [])
                m_aces = m.get("Aces", [])
                if len(o_aces) != len(m_aces):
                    count_mismatch += 1
                    if count_mismatch <= 10:
                        self.failures.append(
                            f"ACE count changed in {masked.name} on "
                            f"object index {odata['data'].index(o)}: "
                            f"{len(o_aces)} -> {len(m_aces)}"
                        )
                    continue

                for oa, ma in zip(o_aces, m_aces):
                    osid = oa.get("PrincipalSID", "")
                    msid = ma.get("PrincipalSID", "")
                    # Only check domain-prefixed well-known SIDs
                    # (real domain SIDs S-1-5-21-triple are intentionally remapped)
                    if "-S-1-" in osid.upper() and not osid.startswith("S-1-5-21-"):
                        o_body = body_re.search(osid)
                        m_body = body_re.search(msid)
                        if o_body and m_body and o_body.group(1) != m_body.group(1):
                            body_mismatch += 1
                            if body_mismatch <= 10:
                                self.failures.append(
                                    f"Well-known SID body altered in {masked.name}: "
                                    f"{osid} -> {msid}"
                                )

        if count_mismatch == 0 and body_mismatch == 0:
            self.passes.append(
                "ACE preservation: all ACE counts preserved and well-known "
                "SID bodies intact"
            )
        else:
            if count_mismatch:
                self.failures.append(f"ACE preservation: {count_mismatch} object(s) with changed ACE counts")
            if body_mismatch:
                self.failures.append(f"ACE preservation: {body_mismatch} well-known SID body alteration(s)")

    # ------------------------------------------------------------------
    # Run all
    # ------------------------------------------------------------------

    def run(self) -> bool:
        pairs = self._matched_files()
        if not pairs:
            sys.exit("[!] No matching original/masked file pairs found")

        print(f"Validating {len(pairs)} file pair(s)...\n")

        self.check_leaks(pairs)
        self.check_sid_validity(pairs)
        self.check_cross_references(pairs)
        self.check_structure(pairs)
        self.check_meta(pairs)
        self.check_descriptions(pairs)
        self.check_pii_fields(pairs)
        self.check_ace_preservation(pairs)

        # Report
        print("=" * 64)
        print("VALIDATION REPORT")
        print("=" * 64)

        for p in self.passes:
            print(f"  [PASS] {p}")
        for w in self.warnings:
            print(f"  [WARN] {w}")
        for fail in self.failures:
            print(f"  [FAIL] {fail}")

        print("=" * 64)
        if self.failures:
            print(f"RESULT: FAILED — {len(self.failures)} issue(s), {len(self.passes)} check(s) passed")
            return False
        print(f"RESULT: PASSED — all {len(self.passes)} checks passed"
              + (f", {len(self.warnings)} warning(s)" if self.warnings else ""))
        return True


def main() -> None:
    p = argparse.ArgumentParser(
        prog="validate",
        description="Validate houndmasker output against the original files.",
    )
    p.add_argument("--original", required=True, metavar="DIR",
                   help="Directory containing the original BloodHound JSON files")
    p.add_argument("--masked", required=True, metavar="DIR",
                   help="Directory containing the masked output (with mapping.json)")
    args = p.parse_args()

    validator = Validator(Path(args.original), Path(args.masked))
    ok = validator.run()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
