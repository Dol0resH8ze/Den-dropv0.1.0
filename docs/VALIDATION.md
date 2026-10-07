# Validation record

Initial implementation checked on 2026-10-07, on Windows with Python 3.12.14.

## Executed checks

- `python -m pytest -q`: **93 passed**.
- `python -m den_drop demo`: encrypted loopback transfer of 262157 bytes;
  byte-for-byte comparison and SHA-256 verification passed.
- The `den-drop` console entry point displays the expected command help.
- Wheel and source distribution built successfully; `twine check` passed for
  both. A separate virtual environment installed the wheel, ran the demo with
  `python -I` (import confirmed from `site-packages`), and passed `pip check`.
  This project has not been published to PyPI.
- An interactive Windows terminal smoke test started a LAN sender using the
  README as a sample and shut it down with the expected invite-expiry message.

Tests exercised empty and multi-chunk files, authenticated ciphertext and
handshake replay rejection, invalid frames and metadata, expiry, concurrent
requests, declined requests, changed source files, no-overwrite publication,
truncation, incorrect hashes, cancellation and partial cleanup, lost receipts,
the CLI host/receive flow, and sender shutdown while approval is pending or
terminal input closes.

Tor tests used controlled fake process output and lifecycle events, plus a real
local SOCKS5 test server. They verified startup readiness, malformed output,
timeout/crash/cancellation cleanup, owned process termination, onion validation,
remote hostname resolution, and stream delivery through the local proxy.

The Windows sandbox prevented some local socket operations and pytest temporary
directory access. Successful runs used explicit permission for these local-only
test operations. No user files were transmitted to an external recipient.

## Not yet verified

After the initial build, the user reported successful use following the
cross-device Tor instructions. This is a manual user report; the checks below
describe the limits of the automated/local validation, not that report.

- A real Tor binary starting, publishing its onion service, and transferring a
  file over the public Tor network. No Tor executable was found on this machine.
- A transfer between two physical devices or over real Wi-Fi/LAN.
- Runtime behavior on Linux. A Windows/Linux, Python 3.12/3.13 CI workflow is
  supplied, but remote CI has not been run as part of this local build.
- Network censorship, antivirus/firewall variants, very large files, or every
  filesystem's link/rename behavior.
- Independent security review or a cryptographic audit. Development review and
  adversarial tests do not provide those guarantees.

## Manual cross-device check

1. Install the project separately on both devices and create an empty recipient
   output directory outside shared/synced folders.
2. LAN: send a harmless sample with `--lan --host YOUR_PRIVATE_IP`; receive with
   `--lan`. Compare the recipient code, approve, and accept.
3. Compare file hashes using `Get-FileHash` on Windows or `sha256sum` on Linux.
4. Confirm the same invite cannot transfer again and an existing filename is
   refused without changing its content.
5. Cancel a larger transfer and check that no partial remains after normal
   cleanup. A forced process kill is a separate crash-recovery limitation.
6. Tor: install an official Tor binary on both devices, run send/receive without
   `--lan`, and repeat while the devices are on separate networks.
7. Confirm Den Drop's own Tor process exits afterwards and any unrelated Tor
   instance remains running.
