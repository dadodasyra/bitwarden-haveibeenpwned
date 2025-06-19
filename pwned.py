import subprocess
import json
import hashlib
import requests
import sys

# ANSI color codes for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def get_hash(password: bytes) -> str:
    m = hashlib.sha1()
    m.update(password)
    return m.hexdigest().upper()

def get_pwned(password_hash: str) -> dict:
    key = password_hash[:5]
    res = requests.get(f"https://api.pwnedpasswords.com/range/{key}")
    res.raise_for_status()
    lines = res.text.splitlines()
    # Map full hash to count
    return {f"{key}{suffix}": int(count) for suffix, count in (line.split(":") for line in lines)}

def get_credentials() -> list:
    result = subprocess.run(["bw", "list", "items"], capture_output=True, text=True)
    items = json.loads(result.stdout)
    return [item for item in items if item.get("login", {}).get("password")]

def main():
    credentials = get_credentials()
    total = len(credentials)
    count_pwned = 0

    for idx, item in enumerate(credentials, start=1):
        # Show live progress
        pct = idx / total * 100
        progress = f"Scanning {idx}/{total} ({pct:5.1f}%)"
        print(progress, end="\r", flush=True)

        pwd = item["login"]["password"].encode("utf-8")
        h = get_hash(pwd)
        results = get_pwned(h)

        if h in results:
            count_pwned += 1
            # Move to new line before printing pwned alert
            print(" " * len(progress), end="\r")  # clear the progress line
            print(
                f"{RED}[PWNED]{RESET} "
                f"{item['name']} ({item['login']['username']}) "
                f"— seen {results[h]:,} times"
            )
            print(item["login"]["password"])

    # Ensure the progress line doesn't overwrite the summary
    print()
    safe = total - count_pwned
    print(f"{GREEN}{safe}{RESET} safe, {RED}{count_pwned}{RESET} pwned out of {total} checked.")

if __name__ == "__main__":
    sys.exit(main())
