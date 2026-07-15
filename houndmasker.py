#!/usr/bin/env python3
"""
main.py
-------
BloodHound CE JSON masker — CLI entrypoint.

Usage
-----
  # First-ever run on a fresh set of files
  python3 houndmasker.py --new file1.json file2.json ...

  # Continue / re-run on same project (loads existing mapping)
  python3 houndmasker.py --extend file1.json file2.json ...

  # Specify custom output directory (default: ./mod)
  python3 houndmasker.py --new --outdir /path/to/output file1.json ...   # custom dir
  python3 houndmasker.py --new file1.json file2.json ...                     # auto: ./modified_files_DD_MM_YY

Output
------
  <outdir>/<original_filename>   — masked JSON (re-importable into BloodHound)
  <outdir>/mapping.json          — persistent token mapping
  Default outdir: ./modified_files_DD_MM_YY  (e.g. ./modified_files_20_06_25)

Safety rules
------------
  --new    : mapping.json must NOT exist in outdir  (prevents overwrite)
  --extend : mapping.json MUST exist in outdir      (prevents orphaned run)
  Both flags are mutually exclusive.
  Neither flag → refuse with a clear explanation.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from mapping import MappingStore
from masker import mask_object


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="houndmasker",
        description="Mask org-specific data in BloodHound CE JSON files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 houndmasker.py --new users.json computers.json groups.json
  python3 houndmasker.py --new --outdir ./masked *.json
  python3 houndmasker.py --extend new_batch.json
        """,
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--new",
        action="store_true",
        help=(
            "First run on a fresh project. "
            "Fails if a mapping.json already exists in the output directory."
        ),
    )
    mode.add_argument(
        "--extend",
        action="store_true",
        help=(
            "Continue an existing project. "
            "Loads the existing mapping.json and extends it with any new entities."
            " Fails if no mapping.json is found."
        ),
    )
    p.add_argument(
        "--outdir",
        default=None,
        metavar="DIR",
        help=(
            "Output directory for masked files and mapping.json. "
            "Default: ./modified_files_DD_MM_YY (date-stamped on each run)."
        ),
    )
    p.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="BloodHound CE JSON file(s) to mask.",
    )
    return p


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

def validate_inputs(args: argparse.Namespace, mapping_path: Path) -> None:
    """
    Enforce the --new / --extend safety contract and validate input files.
    Exits with a descriptive error on any violation.
    """
    errors: list[str] = []

    # --- Mode checks ---
    if args.new and mapping_path.exists():
        errors.append(
            f"[!] --new was specified but a mapping file already exists:\n"
            f"    {mapping_path}\n"
            f"    If you want to continue an existing project, use --extend.\n"
            f"    If you truly want to start fresh, remove the mapping file first."
        )

    if args.extend and not mapping_path.exists():
        errors.append(
            f"[!] --extend was specified but no mapping file was found at:\n"
            f"    {mapping_path}\n"
            f"    If this is a new project, use --new instead."
        )

    # --- Input file checks ---
    missing = [f for f in args.files if not Path(f).exists()]
    if missing:
        errors.append(
            "[!] The following input files do not exist:\n"
            + "\n".join(f"    {f}" for f in missing)
        )

    non_json = [f for f in args.files if not f.lower().endswith(".json")]
    if non_json:
        errors.append(
            "[!] The following files do not have a .json extension "
            "(are they BloodHound CE output files?):\n"
            + "\n".join(f"    {f}" for f in non_json)
        )

    # --- Check for readable JSON ---
    bad_json = []
    for fpath in args.files:
        if Path(fpath).exists():
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if "meta" not in data or "data" not in data:
                    bad_json.append(
                        f"    {fpath}  ← missing 'meta' or 'data' key "
                        f"(not a BloodHound CE file?)"
                    )
            except json.JSONDecodeError as exc:
                bad_json.append(f"    {fpath}  ← JSON parse error: {exc}")
    if bad_json:
        errors.append("[!] Invalid BloodHound CE files:\n" + "\n".join(bad_json))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------

def process_file(input_path: Path, output_path: Path, store: MappingStore) -> dict:
    """
    Load one BloodHound CE JSON file, mask every object in data[], and write
    the result to output_path.  Returns a stats dict.
    """
    with open(input_path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    meta     = raw["meta"]
    obj_type = meta.get("type", "unknown")
    objects  = raw["data"]
    total    = len(objects)

    print(f"\n  Processing: {input_path.name}")
    print(f"    type={obj_type}  objects={total}")

    masked_objects = []
    for i, obj in enumerate(objects, 1):
        masked = mask_object(obj, obj_type, store)
        masked_objects.append(masked)
        if i % 500 == 0 or i == total:
            print(f"    [{i}/{total}]", end="\r")

    print()  # newline after progress

    # Write output — preserve meta exactly (not org-specific)
    output = {"data": masked_objects, "meta": meta}
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, separators=(",", ":"), ensure_ascii=False)

    size_kb = output_path.stat().st_size // 1024
    print(f"    Written: {output_path}  ({size_kb} KB)")
    return {"type": obj_type, "count": total}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser  = build_parser()
    args    = parser.parse_args()

    # Build default output dir name if not explicitly provided
    if args.outdir is None:
        from datetime import datetime
        datestamp = datetime.now().strftime("%d_%m_%y")
        args.outdir = f"./modified_files_{datestamp}"

    outdir  = Path(args.outdir)
    mapping_path = outdir / "mapping.json"

    # Create output directory
    outdir.mkdir(parents=True, exist_ok=True)

    # Safety validation (exits on error)
    validate_inputs(args, mapping_path)

    # Initialise mapping store
    store = MappingStore(mapping_path)
    if args.new:
        store.init_new()
    else:  # --extend
        store.load_existing()

    print(f"\n[+] Output directory: {outdir.resolve()}")
    print(f"[+] Files to process: {len(args.files)}")

    # Process files
    t_start = time.monotonic()
    stats   = []

    for fpath_str in args.files:
        input_path  = Path(fpath_str)
        output_path = outdir / input_path.name
        result = process_file(input_path, output_path, store)
        stats.append(result)

    elapsed = time.monotonic() - t_start

    # Resolve leftover domain/triple placeholder entries in the mapping
    fin = store.finalize()

    # Final summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total_objects = sum(s["count"] for s in stats)
    print(f"  Files processed : {len(stats)}")
    print(f"  Total objects   : {total_objects}")
    print(f"  Elapsed         : {elapsed:.1f}s")
    if fin["resolved"]:
        print(f"  Placeholders resolved: {fin['resolved']}")
    if fin["unresolved"]:
        print(f"  Unresolved placeholders: {len(fin['unresolved'])} "
              f"(domains/triples with no counterpart in the dataset)")
    print(f"\n  Mapping totals:")
    for bucket, count in store.summary().items():
        if count:
            print(f"    {bucket:<16}: {count}")
    print(f"\n  Mapping file    : {mapping_path}")
    print(f"  Masked files in : {outdir.resolve()}")
    print("=" * 60)


if __name__ == "__main__":
    main()
