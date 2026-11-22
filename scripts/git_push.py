"""Convenience script to push to GitHub using GITHUB_TOKEN configured in .env.
"""
import os
import re
import sys
import subprocess
from pathlib import Path

def main():
    repo_root = Path(__file__).resolve().parent.parent
    env_file = repo_root / ".env"
    if not env_file.exists():
        print("[-] Error: .env file not found.", file=sys.stderr)
        sys.exit(1)

    content = env_file.read_text(encoding="utf-8")
    m = re.search(r"^GITHUB_TOKEN=(.+)$", content, re.MULTILINE)
    if not m:
        print("[-] Error: GITHUB_TOKEN not found in .env.", file=sys.stderr)
        sys.exit(1)

    token = m.group(1).strip()
    remote_url = f"https://{token}@github.com/siddick369-sys/smart-monitor.git"

    # Default to pushing current branch (main) if no arguments provided
    args = ["git", "push", remote_url] + (sys.argv[1:] if len(sys.argv) > 1 else ["main"])
    res = subprocess.run(args, cwd=repo_root)
    sys.exit(res.returncode)

if __name__ == "__main__":
    main()
