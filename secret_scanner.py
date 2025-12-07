# secret_scanner.py

import os
import re
import sys
import argparse
from pathlib import Path

# Default junk / noisy directories to skip
DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn",
    ".idea", ".vscode",
    "node_modules",
    ".venv", "venv", "env",
    "__pycache__",
    "dist", "build",
}

# Default file extensions that are usually binary or not useful to scan
DEFAULT_SKIP_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".class", ".jar",
}


def build_pattern() -> re.Pattern:
    regPattern = r"""
    (
        (?:mongodb|postgres|mysql|jdbc|redis|ftp|smtp)[\s_\-=:][A-Za-z0-9+=._-]{10,}|
        Azure_Storage_(?:AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken)[^\n]+|
        ClientSecret"\svalue=.+|
        (?:AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)=\S{10,}|
        AccountKey=\S{10,}|
        secret_key_base:\s.[A-Za-z0-9_.-]{12,}|
        secret(?:\s|:|=).+[A-Za-z0-9_.-]{12,}|
        Bearer\s.\S{11,}|
        api[_-](?:key|token)(?::|=).[A-Za-z0-9_.-]{10,}|
        ssh-rsa\s+[A-Za-z0-9+/=]+|
        -----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----|
        (?:password|passwd|pwd|Password|PASSWORD)\s*[:=]\s*["']?[^\s"']{8,}|
        eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}
    )
    """
    return re.compile(regPattern, re.IGNORECASE | re.VERBOSE)


def is_binary_file(path: Path, blocksize: int = 1024) -> bool:
    """
    Heuristic: if the first chunk contains a null byte, treat it as binary.
    If we can't read it, also treat as binary/junk to be safe.
    """
    try:
        with path.open("rb") as f:
            chunk = f.read(blocksize)
        return b"\0" in chunk
    except OSError:
        return True


def scan_directory(
    root_path: Path,
    output_path: Path,
    skip_dirs=None,
    skip_exts=None,
    max_file_size_bytes: int | None = 5 * 1024 * 1024,
    pattern: re.Pattern | None = None,
):
    """
    function that:
    - walks root_path
    - skips junk dirs/exts, large files, and binaries
    - searches each text file line-by-line
    - writes matches to output_path
    - returns a list of match dicts for testing
    """
    # Merge default skip dirs with any user-provided ones
    if skip_dirs is None:
        effective_skip_dirs = set(DEFAULT_SKIP_DIRS)
    else:
        effective_skip_dirs = set(DEFAULT_SKIP_DIRS).union(skip_dirs)

    # Merge default skip exts with any user-provided ones
    if skip_exts is None:
        effective_skip_exts = set(DEFAULT_SKIP_EXTS)
    else:
        # Normalize to ".ext" lowercase and union
        extra = {
            e.lower() if e.startswith(".") else f".{e.lower()}"
            for e in skip_exts
        }
        effective_skip_exts = set(DEFAULT_SKIP_EXTS).union(extra)

    if pattern is None:
        pattern = build_pattern()

    matches_found: list[dict] = []

    root_path = root_path.resolve()

    with output_path.open("w", encoding="utf-8") as cred_file:
        for current_root, dirnames, filenames in os.walk(root_path):
            # In-place filter of directories so os.walk doesn't even descend into them
            dirnames[:] = [d for d in dirnames if d not in effective_skip_dirs]

            for filename in filenames:
                file_path = Path(current_root) / filename

                # Skip by extension
                #ext = file_path.suffix.lower()
                ext = ("." + file_path.name.split(".")[-1].lower()) if "." in file_path.name else ""
                if ext in effective_skip_exts:
                    continue

                # Skip by file size, if configured
                if max_file_size_bytes is not None:
                    try:
                        if file_path.stat().st_size > max_file_size_bytes:
                            continue
                    except OSError:
                        # Can't stat it? Skip it.
                        continue

                # Skip binary files
                if is_binary_file(file_path):
                    continue

                # Scan file line-by-line for matches
                try:
                    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            for m in pattern.finditer(line):
                                match_text = m.group(0)
                                record = {
                                    "file": str(file_path),
                                    "line": lineno,
                                    "match": match_text,
                                }
                                matches_found.append(record)
                                cred_file.write(f"{file_path}:{lineno} | {match_text}\n")
                except Exception as e:
                    # You can swap this for logging if desired
                    print(f"Error reading file {file_path}: {e}")

    return matches_found


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan a directory for potential credentials/secrets."
    )
    parser.add_argument(
        "path",
        help="Directory to scan.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="docsCred.txt",
        help="Output file path (default: docsCred.txt)",
    )
    parser.add_argument(
        "--max-size-mb",
        type=int,
        default=5,
        help="Maximum file size in megabytes to scan (default: 5). "
             "Use 0 or a negative value to disable the size limit.",
    )
    parser.add_argument(
        "--skip-dir",
        action="append",
        default=[],
        help="Additional directory name to skip. Can be passed multiple times.",
    )
    parser.add_argument(
        "--skip-ext",
        action="append",
        default=[],
        help="Additional file extension to skip (e.g. .log). "
             "Can be passed multiple times.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    root = Path(args.path).expanduser()
    output = Path(args.output).expanduser()

    if args.max_size_mb and args.max_size_mb > 0:
        max_bytes = args.max_size_mb * 1024 * 1024
    else:
        max_bytes = None

    extra_dirs = set(args.skip_dir) if args.skip_dir else None
    extra_exts = set(args.skip_ext) if args.skip_ext else None

    print(f"Scanning directory: {root}")
    print(f"Writing results to: {output}")

    matches = scan_directory(
        root_path=root,
        output_path=output,
        skip_dirs=extra_dirs,
        skip_exts=extra_exts,
        max_file_size_bytes=max_bytes,
    )

    print(f"Scan complete. {len(matches)} potential secret(s) found.")


if __name__ == "__main__":
    main(sys.argv[1:])

