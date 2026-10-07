# Den Drop

**Private file handoffs. No accounts.**

Send one file to one person from your terminal. Your computer hosts the transfer;
there is no Den Drop cloud server, signup, or permanent upload. The recipient
needs Den Drop too, and both devices must stay online until delivery finishes.

**Experimental prototype, not an independently audited secure file-transfer tool.**
This is a separate project from [Den](https://github.com/Dol0resH8ze/hush).

## What it does

- Hosts a transfer automatically when you run `den-drop send FILE`.
- Creates a secret invite with a default ten-minute approval window.
- Requires the sender to approve the recipient, then the recipient to accept
  the filename and size before downloading.
- Encrypts file metadata, chunks, and the delivery receipt using PyNaCl/libsodium.
- Streams in bounded chunks with a progress bar, without loading the whole file
  into memory or making a second sender-side copy.
- Verifies the received size and SHA-256 digest before publishing the final file.
- Refuses to overwrite an existing file. Removes partial downloads on handled
  failures and cancellation.
- Consumes the invite when the sender approves one recipient, even if that
  transfer fails. Start a new offer to retry.
- Runs on Python 3.12+ with Windows and Linux support in the source and CI matrix.

## Two connection modes

| Mode | Use it for | Setup | Privacy boundary |
| --- | --- | --- | --- |
| Tor (default) | Different networks, including networks behind CGNAT | Install Tor once; Den Drop starts and configures its own instance | Peers connect via an onion service; no direct-network fallback |
| LAN (`--lan` on both devices) | Same private network, or a local test | No Tor needed; sender specifies their local IP | Direct connection; IP addresses are visible |

The sender is the file host. There is no separate relay command or third-party
file storage. In Tor mode, encrypted traffic still travels through the Tor
network; "self-hosted" does not mean that all network traffic stays on your PC.

## Install from this project

This prototype has **not been published to PyPI**. Install this checkout rather
than assuming that a package with a similar name belongs to this project.

Windows PowerShell, inside the project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\den-drop.exe --help
```

Linux, inside the project folder:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/den-drop --help
```

The examples below use `den-drop`. Activate the environment in each terminal
with `.\.venv\Scripts\Activate.ps1` on Windows or `source .venv/bin/activate`
on Linux. Alternatively, use the full executable path above. `python -m den_drop`
works with the environment's Python as well.

Install independently on each PC. Copy the source project, not `.venv`, when
moving between computers.

## Quick local demo

```text
den-drop demo
```

This starts a loopback host and recipient, transfers a generated sample with
real encryption, compares the bytes, and deletes the demo files. It does not
use Tor, cross a network, or demonstrate anonymity.

## Send on the same network

1. On Windows, run `ipconfig` to find the sender's private IPv4 address for the
   active Wi-Fi/Ethernet adapter. On Linux, use `ip address`.
2. On the sender, replace the example address and filename below:

```text
den-drop send report.pdf --lan --host 192.168.1.20
```

3. Share the full `drop1.` invite privately. Keep the sender terminal open.
4. On the recipient, select an existing destination directory:

```text
den-drop receive --lan --output Downloads
```

`Downloads` here is relative to the current directory. Use a full path to your
Downloads folder if needed. To save in the current folder, omit `--output`.

5. Paste the invite into the hidden prompt. The recipient sees their session
   code; compare it with the code shown to the sender through your private
   communication channel.
6. The sender answers `y` to approve. The recipient reviews the filename and size
   and answers `y` to receive it. Default answers are no.
7. Wait for the verified delivery message. The host stops automatically.

For a test in two terminals on one computer, use `--host 127.0.0.1` and receive
into a different directory so the original filename does not collide.

If Windows Firewall prompts, allow the Python process only on your trusted
private network. Guest Wi-Fi client isolation or a firewall may block LAN
transfers. This mode accepts private/loopback numeric addresses; it is not an
automatic internet NAT-traversal feature and does not open router ports.

## Send across different networks with Tor

### One-time prerequisite on each PC

Install Tor once. Den Drop currently does not download or bundle a Tor binary.

- **Windows:** obtain and verify the appropriate Expert Bundle from the
  [Tor Project](https://www.torproject.org/download/tor/), then extract the entire
  bundle, keeping its DLLs beside `tor.exe`. You can pass its location with
  `--tor-exe`. Existing bundles under `%LOCALAPPDATA%\HushTor\bundle` or
  `%LOCALAPPDATA%\DenDropTor\bundle` are discovered automatically.
- **Linux:** install the `tor` executable using the
  [Tor Project's distribution guidance](https://support.torproject.org/little-t-tor/).
  It is discovered on `PATH`.

You do not need to create a `torrc`, run `den relay`, read a `hostname` file, or
open router ports. Den Drop starts a separate Tor instance with its own temporary
configuration, local SOCKS port, and (for the sender) fresh onion service. It
does not modify your existing Den/Tor configuration or stop other Tor processes.

### Every transfer

Sender:

```text
den-drop send report.pdf
```

Recipient:

```text
den-drop receive --output Downloads
```

If Tor is not discovered, add its path to either command, for example:

```powershell
den-drop send report.pdf --tor-exe "C:\Tools\tor\tor.exe"
```

Den Drop prints Tor bootstrap progress. Share the resulting invite privately,
paste it on the recipient, compare the recipient code, and approve/accept as in
the LAN steps. Neither side uses `--lan` here.

Tor bootstrap can take up to three minutes before a startup timeout, and onion
connection setup can take up to two minutes. A newly created onion service may
need time to become reachable even after bootstrap reaches 100%. There is no
direct connection fallback. Bridges and censored-network setup are not supported
in this first version.

## Commands and lifecycle

| Command / option | Meaning |
| --- | --- |
| `den-drop send FILE` | Host one regular file over Tor |
| `den-drop receive` | Enter an invite privately and receive into the current directory |
| `--lan` | Explicitly allow direct LAN mode on that device |
| `send --host ADDRESS` | Numeric private interface address; required with `--lan` |
| `send --port NUMBER` | Local listening port; default 0 chooses an available port |
| `send --expires SECONDS` | Approval deadline, 1–86400 seconds; default 600 |
| `receive --output DIRECTORY` | Existing destination directory; never overwrite |
| `--tor-exe PATH` | Explicit installed Tor executable, for either send or receive |
| `den-drop demo` | Self-contained loopback demonstration |
| `den-drop --help` / `--version` | Usage / version |
| Ctrl+C | Cancel and shut down this session |

The approval deadline starts after the host is ready and the invite is created.
Approving consumes the invite; an approved transfer can finish after its expiry.
Denied requests leave it available until expiry. Approval/acceptance and idle
network operations have timeouts. Failure after approval requires a fresh offer.

The receiver saves through a randomly named `.den-drop-*.part` file in the
destination directory, then publishes it only after verifying all data. Existing
names are refused, including if a collision appears during transfer. A lost final
receipt can leave the receiver with a verified file while the sender reports
unconfirmed completion; check the receiver before trying again.

Version 0.1 has no resume, folder transfer, multiple recipients, persistent
identities, offline delivery, file previews, or automatic opening of downloads.
Zip a folder yourself if you want to send it as one file.

## Privacy and security boundaries

- Invites are encoded, **not encrypted**. They contain a bearer secret, endpoint,
  expiry, and sender public key. Share the entire invite only with your intended
  recipient; keep it out of screenshots and public posts.
- Approval identifies a session key, not a real-world person. Anyone who obtains
  the invite can request entry. Compare codes through a trusted channel.
- File metadata and content are encrypted over the connection. Traffic size and
  timing remain observable. Encryption does not remove identifying metadata
  inside the file itself.
- No central service stores files. The original file remains on the sender's
  disk; received and partial files are plaintext on the recipient's disk.
- Closing a transfer does not revoke a recipient's saved copy.
- Tor does not guarantee anonymity against traffic correlation or compromised
  endpoints. LAN mode deliberately exposes network addresses.
- Invites and keys are held in Python memory; secure memory erasure is not
  guaranteed. Terminal scrollback, clipboard history, backups, swap and crash
  dumps can retain information.
- Managed Tor writes temporary runtime data and onion keys outside the project.
  Normal shutdown attempts to remove them. A crash, forced kill, power loss, or
  filesystem failure can leave runtime data or partial downloads behind.

See [SECURITY.md](SECURITY.md) and [protocol notes](docs/PROTOCOL.md).

## Development and checks

```text
python -m pip install -e ".[dev]"
python -m pytest -q
python -m den_drop demo
python -m build
python -m twine check dist/*
```

Use the virtual environment's Python. Tests cover transfer success and failure,
invites, framing, authenticity, output-file safety, CLI flow, and mocked Tor
lifecycle plus a local SOCKS server. They are not a security audit. See
[validation notes](docs/VALIDATION.md) for what was actually run.

## License

[MIT](LICENSE).

