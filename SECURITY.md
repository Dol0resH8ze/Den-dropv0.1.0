# Security status

Den Drop 0.1 is experimental software with a new, unaudited application protocol.
Its use of established cryptographic primitives is not evidence of a secure
protocol or guaranteed anonymity. Do not rely on it for high-risk transfers.

## Intended boundary

The sender deliberately chooses a regular local file. The receiver deliberately
chooses an existing trusted directory and must accept the authenticated filename
and size. Both machines, their Python environments, and the installed Tor binary
are trusted. An attacker can observe or alter network traffic, or connect to the
file host. An invite holder can request a transfer, but cannot bypass sender
approval. The sender may send malicious file content; Den Drop does not inspect,
sandbox, preview, or execute received files.

No central Den Drop relay or account provider exists. The sender's app hosts the
transfer. LAN mode exposes numeric IP addresses. Tor mode starts a local Tor
client and onion service; Tor relays and traffic correlation remain relevant.
There is no automatic fallback between modes.

## What is implemented

- A 256-bit random bearer secret plus pinned offer-specific X25519 public key
  in the invite; session code comparison for the requesting recipient.
- Fresh challenge authentication, directional session keys, authenticated
  encryption with ordered implicit nonces, bounded frames and idle timeouts.
- Encrypted filename, size, file chunks, final digest, and receipt.
- Explicit sender and receiver consent; one irreversible approved attempt.
- Canonical invites, checksummed v3 onion addresses and restricted numeric LAN
  destinations. A LAN invite additionally requires `receive --lan` at the CLI.
- Portable basename validation, exclusive partial-file creation and publication
  without replacement after size/hash verification.
- Owned-process termination and temporary runtime cleanup on normal completion,
  cancellation, and handled startup failures.

## Limitations

The invite itself is not encrypted. Anyone who sees it learns the endpoint and
can request the transfer. A leaked invite does not reveal file plaintext by
itself, but the app cannot identify which real person is using it.

There are no persistent identities, delivery retries, resumable transfers,
multi-recipient sharing, or key ratchets. Session keys are ephemeral in intent,
but Python does not guarantee secure erasure and no audited forward-secrecy
claim is made. Compromise of an endpoint or the relevant session keys exposes
its file content. A recipient can retain or redistribute the file.

Traffic length, timing, network endpoints, and public handshake fields remain
observable. File contents may themselves contain identifying metadata.

The receiving disk holds plaintext partial/complete files. Normal cancellation
deletes the partial file; deletion is not secure erasure. Forced termination,
power loss, antivirus/file locks, filesystem errors, and crashes can leave
partials or temporary Tor state. OS swap, clipboard history, terminal scrollback,
backups, and shared/synced destination folders may retain data. Use a private
non-synced destination if copies in a cloud backup would be inappropriate.

The local source path and destination directory must be trusted against
concurrent modification by another local actor. The application blocks remote
path traversal and ordinary file collisions; it is not a sandbox against an
attacker controlling the user's filesystem or Python installation.

There is a cap on simultaneous client handlers, but no comprehensive DoS
protection. An attacker can occupy handshake slots. A peer can keep an approved
session active by slowly sending traffic within idle deadlines.

## Reporting

Use a private channel to the maintainer for vulnerabilities where possible.
Never include real invites, private keys, private file contents, or an unredacted
terminal screenshot in public reports. There is no dedicated security contact
configured for this new project yet.

