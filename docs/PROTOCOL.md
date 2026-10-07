# Den Drop v1 protocol notes

This describes the implementation, not a reviewed cryptographic specification.
The protocol is independent of Den's chat wire protocol and invites.

## Invitation and admission

`drop1.` followed by canonical, unpadded base64url JSON carries the mode, host,
port, Unix expiry, 32-byte random secret and sender X25519 public key. Invites
are bounded to 2048 characters. The maximum approval lifetime is 24 hours;
the default is 600 seconds. The sender enforces its own expiry, so editing the
invite's expiry cannot extend the server's approval window.

Tor endpoints must be checksummed canonical v3 onion names. LAN endpoints must
be canonical numeric RFC1918 IPv4, IPv4 loopback, IPv6 loopback, or IPv6 ULA
addresses. Hostnames, wildcard addresses, public addresses, and link-local scope
identifiers are rejected. The receiver CLI requires explicit consent to LAN mode
before opening a connection. The protocol itself is independent of the connector.

1. The server sends `DEN-DROP/1\0` and a new random 32-byte challenge.
2. The receiver generates a fresh X25519 key pair and sends its 32-byte public
   key plus an HMAC-SHA256 proof keyed by the invite secret over the protocol
   domain, `client-proof\0`, both public keys and the challenge.
3. The server verifies the proof before asking for approval. It validates the
   X25519 shared secret and admits only one pending approval prompt at a time.
4. Both sides derive two 32-byte keys using keyed BLAKE2b: the invite secret is
   the BLAKE2b key; input binds the protocol domain, X25519 shared material,
   both public keys, fresh challenge and the direction label.
5. Sender approval consumes the offer. Rejecting before approval does not.
   A successful approval sends encrypted metadata authenticated under the
   offer's pinned sender key. Receiver acceptance is also encrypted.

The receiver proves invite possession, not a global identity. The UI displays
the first 16 hex characters of SHA-256 of a public key as a session code. Compare
the requesting recipient's code through a trusted channel.

## Framing and encrypted transfer

All frames have a four-byte unsigned big-endian length. General frames are
bounded to 65536+256 bytes; handshake reads impose smaller exact bounds.
File chunks are at most 65536 bytes, using bounded streaming and backpressure.

Each direction uses a separate libsodium SecretBox key (XSalsa20-Poly1305).
Nonces are implicit 24-byte big-endian sequence numbers, starting at zero and
incrementing for each message in that direction. Keys change with each server
challenge and recipient key. A reordered, corrupted, duplicated, or cross-session
ciphertext fails authentication. A channel is abandoned on a frame failure.

The authenticated plaintext begins with a one-byte type:

| Type | Purpose |
| --- | --- |
| `E` | Request unavailable or declined |
| `M` | Canonical JSON filename and byte count |
| `A` | Recipient accepts |
| `X` | Recipient declines |
| `D` | File data chunk |
| `F` | Canonical JSON final size and SHA-256 digest |
| `R` | Recipient's matching final verification receipt |

Metadata filenames are validated as portable basenames. Existing destination
names, separators, path traversal, control characters, Windows reserved names,
alternate-data-stream syntax, and trailing dots/spaces are rejected. A receiver
creates an exclusive random partial file only after acceptance. It checks chunk
sizes against the advertised total and verifies the final size and hash, flushes
and fsyncs the partial, then publishes without replacement. Windows uses rename's
no-overwrite behavior; POSIX uses a same-directory hard link followed by unlink.
Filesystems that do not support the required publication operation fail closed.

The sender checks the source file's identity, size and modification time against
the original offer and during streaming. This detects ordinary changes, not a
malicious local actor controlling source storage.

The final receipt confirms receiver verification and publication. A lost receipt
does not erase the receiver's verified file; the sender reports unconfirmed
completion instead of assuming delivery. Once approval consumes an invite, a
failed transfer cannot reuse it.

## Tor lifecycle

Each invocation discovers an installed binary, creates a temporary configuration
and data directory, and starts only its own Tor process. SOCKS listens on a
random loopback port with onion-only destinations and remote resolution. Sender
Tor forwards onion port 8765 to the already-open loopback file host. Neither a
system-wide configuration nor any existing Tor service is changed.

Readiness requires bootstrap 100%, a discovered SOCKS listener, and (for the
sender) a valid hostname file. This is not proof of onion descriptor propagation.
Shutdown terminates only the owned process and attempts to delete owned runtime
data. Unexpected machine/process death can leave artifacts.

Primitive and configuration references:

- [PyNaCl SecretBox](https://pynacl.readthedocs.io/en/latest/secret/)
- [PyNaCl public-key encryption](https://pynacl.readthedocs.io/en/latest/public/)
- [Tor onion services](https://community.torproject.org/onion-services/setup/)
- [Tor configuration manual](https://manpages.debian.org/trixie/tor/torrc.5.en.html)

