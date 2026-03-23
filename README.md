# TeamPCP / Trivy Compromise Checker

A single-file bash script that checks a machine for indicators of compromise (IOCs) from the [TeamPCP supply chain attack on Trivy v0.69.4](https://www.aquasec.com/blog/teamtnt-returns-as-teampcp-with-new-trivy-attack/) and the related [CanisterWorm npm supply chain attack](https://socket.dev/blog/canisterworm-malware-targets-npm-packages) (March 2026). Supports both Linux and macOS.

## Usage

Download, inspect, then run:

```bash
curl -fsSL https://raw.githubusercontent.com/matthewdeaves/teampcp-checker/refs/heads/master/check.sh -o check_teampcp.sh
less check_teampcp.sh   # review before running
bash check_teampcp.sh
```

Or clone and run:

```bash
git clone https://github.com/matthewdeaves/teampcp-checker.git
cd teampcp-checker
git verify-commit HEAD 2>/dev/null || echo "unsigned commit — review check.sh before running"
./check.sh
```

**Works on Linux and macOS.** On Linux it uses `journalctl`, systemd paths, and standard utilities. On macOS it uses compatible alternatives (`shasum`, `stat -f`, `base64 -D`, etc.). Some checks (systemd services, journalctl) are Linux-only and are automatically skipped on macOS.

No dependencies beyond standard system utilities. If `gh` (GitHub CLI) is installed and authenticated, it will auto-detect your GitHub username for the GitHub repo and SSH key checks.

## What it checks

| # | Check | Severity |
|---|-------|----------|
| 1 | Trivy version (flags v0.69.4 as compromised) | FAIL |
| 2 | Persistence payloads (`sysmon.py`, `pgmon/service.py`, `/tmp/pglog`, `/tmp/.pg_state`) | FAIL |
| 3 | Unfamiliar systemd user services/timers | WARN |
| 4 | `tpcp.tar.gz` exfil archive on disk | FAIL |
| 5 | `tpcp-docs` repo on your GitHub account | FAIL |
| 6 | C2 domains in logs (`aquasecurtiy.org`, ICP canister, Cloudflare tunnel) | FAIL |
| 7 | C2 IP `45.148.10.212` in logs | FAIL |
| 8 | Suspicious running processes (`sysmon.py`, `pgmon/service.py`) | FAIL |
| 9 | Local `tpcp-docs` directory clone | FAIL |
| 10 | Recently modified files in systemd user dir | WARN |
| 11 | Suspicious npm global packages (CanisterWorm) | FAIL/WARN |
| 12 | SSH keys modified since attack window | WARN |
| 13 | Suspicious cron jobs | WARN |
| 14 | Cloud credential files (AWS/GCP/Azure) modified recently | WARN |
| 15 | Compromised Trivy Docker images (0.69.4, 0.69.5, 0.69.6) | FAIL |
| 16 | Trivy binary SHA256 against known malicious hashes | FAIL |
| 17 | Compromised npm scopes (`@EmilGroup`, `@opengov`, `@teale.io`, `@airtm`, `@pypestream`) | FAIL |
| 18 | GitHub Actions workflows referencing trivy-action by mutable tag (local) | WARN |
| 19 | GitHub repos using trivy-action/setup-trivy (via API, requires `gh`) | FAIL/PASS |
| 20 | GitHub account security log + SSH keys added during attack window | FAIL/WARN |

## Example output

```
TeamPCP / Trivy Compromise Checker
======================================
Checking: myhost as matt at Mon Mar 23 05:31:18 UTC 2026

[1] Trivy installation
✓ Trivy version 0.69.3 (not the compromised 0.69.4)
  → Path: /usr/local/bin/trivy | Modified: 2026-03-14
...
======================================
RESULT: No signs of compromise found.
```

## If you find something

1. Disconnect the machine from the network
2. Rotate all credentials accessible from the machine (GitHub tokens, SSH keys, AWS/GCP/Azure creds, API keys, database passwords)
3. Check your GitHub account for a `tpcp-docs` repo and delete it
4. Rebuild from a known-good image if fully compromised

## License

MIT
