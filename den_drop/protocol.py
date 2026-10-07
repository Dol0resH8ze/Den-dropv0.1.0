"""Den Drop v1: an experimental, unaudited, one-recipient encrypted stream.

An invite contains a random 256-bit bearer secret and an offer-specific X25519
public key. A fresh server challenge binds the client's HMAC-SHA256 proof to
this connection. Session keys use keyed BLAKE2b over X25519 shared material,
both public keys and the challenge, with separate directional domain labels.
SecretBox (XSalsa20-Poly1305) authenticates every subsequent frame. Each direction
uses its own increasing 192-bit nonce, starting at zero; nonces are implicit.
Metadata, data, the final SHA256/size, and the receiver's receipt are encrypted.
Only fixed handshake fields, framing lengths, timing, and endpoints are exposed.

Possessing the invite authorizes requesting a transfer, not skipping approval.
Approval irreversibly consumes the offer, including if the transfer then fails.
Receiver output is published without replacement only after complete verification.
The protocol is new, despite using established cryptographic primitives.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import tempfile
import time
from typing import Awaitable, Callable
import unicodedata
from dataclasses import dataclass

from nacl.bindings import crypto_scalarmult
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from nacl.secret import SecretBox

CHUNK_SIZE = 64 * 1024
MAX_FRAME = CHUNK_SIZE + 256
MAX_INVITE = 2048
HANDSHAKE_TIMEOUT = 30
IDLE_TIMEOUT = 120
APPROVAL_TIMEOUT = 120
MAX_CONNECTIONS = 8
MAX_FILE_SIZE = (1 << 63) - 1
_MAGIC = b"DEN-DROP/1\x00"
_LAN_NETWORKS = tuple(ipaddress.ip_network(s) for s in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"
))

Approve = Callable[[str], Awaitable[bool]]
Accept = Callable[[str, int, str], Awaitable[bool]]
Progress = Callable[[int, int], None]
Connect = Callable[[str, int, str], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


class DropError(Exception):
    """A safe-to-display error without secret invitation material."""


@dataclass(frozen=True, repr=False)
class Invite:
    host: str
    port: int
    mode: str
    expires: int
    secret: bytes
    sender_key: bytes

    def __repr__(self) -> str:
        return f"Invite(mode={self.mode!r}, expires={self.expires}, secret=<redacted>)"


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(value: str, length: int | None = None) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise DropError("Invalid invite encoding.")
    try:
        data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise DropError("Invalid invite encoding.") from exc
    if _encode(data) != value or (length is not None and len(data) != length):
        raise DropError("Invalid invite encoding.")
    return data


def _json(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _unjson(data: bytes) -> dict:
    try:
        obj = json.loads(data)
        if not isinstance(obj, dict) or _json(obj) != data:
            raise ValueError
        return obj
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DropError("Invalid protocol message.") from exc


def validate_endpoint(host: str, port: int, mode: str) -> None:
    if type(port) is not int or not 1 <= port <= 65535 or not isinstance(host, str):
        raise DropError("Invalid transfer endpoint.")
    if mode == "tor":
        if not re.fullmatch(r"[a-z2-7]{56}\.onion", host):
            raise DropError("Tor invites require a valid v3 onion address.")
        raw = base64.b32decode(host[:-6].upper())
        checksum = hashlib.sha3_256(b".onion checksum" + raw[:32] + raw[34:]).digest()[:2]
        if raw[34:] != b"\x03" or not hmac.compare_digest(raw[32:34], checksum):
            raise DropError("Tor invites require a valid v3 onion address.")
    elif mode == "lan":
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise DropError("LAN invites require a numeric private or loopback address.") from exc
        if "%" in host or str(address) != host or not any(address in net for net in _LAN_NETWORKS):
            raise DropError("LAN invites require a numeric private or loopback address.")
    else:
        raise DropError("Unknown transfer mode.")


def parse_invite(token: str) -> Invite:
    if not isinstance(token, str) or len(token) > MAX_INVITE or not token.startswith("drop1."):
        raise DropError("Invalid Den Drop invite.")
    obj = _unjson(_decode(token[6:]))
    if set(obj) != {"host", "port", "mode", "expires", "secret", "sender"}:
        raise DropError("Invalid Den Drop invite.")
    validate_endpoint(obj["host"], obj["port"], obj["mode"])
    now = time.time()
    if type(obj["expires"]) is not int or not now < obj["expires"] <= now + 86401:
        raise DropError("This invite has expired or has an invalid expiry.")
    sender = _decode(obj["sender"], 32)
    secret = _decode(obj["secret"], 32)
    return Invite(obj["host"], obj["port"], obj["mode"], obj["expires"], secret, sender)


def validate_filename(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise DropError("Unsafe or unsupported file name.")
    try:
        encoded = name.encode("utf-8")
    except UnicodeError as exc:
        raise DropError("Unsafe or unsupported file name.") from exc
    if len(encoded) > 240:
        raise DropError("Unsafe or unsupported file name.")
    if name in {".", ".."} or name[-1] in " ." or any(c in '<>:"/\\|?*' or unicodedata.category(c).startswith("C") for c in name):
        raise DropError("Unsafe or unsupported file name.")
    stem = name.split(".")[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem):
        raise DropError("Unsafe or unsupported file name.")
    return name


async def _read_frame(reader: asyncio.StreamReader, maximum: int = MAX_FRAME, timeout: float = IDLE_TIMEOUT) -> bytes:
    try:
        async with asyncio.timeout(timeout):
            length = struct.unpack("!I", await reader.readexactly(4))[0]
            if not 1 <= length <= maximum:
                raise DropError("Invalid or oversized transfer frame.")
            return await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise DropError("Connection closed before the transfer completed.") from exc
    except TimeoutError as exc:
        raise DropError("Transfer timed out.") from exc


async def _write_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    if not 1 <= len(data) <= MAX_FRAME:
        raise DropError("Invalid or oversized transfer frame.")
    writer.write(struct.pack("!I", len(data)) + data)
    try:
        await asyncio.wait_for(writer.drain(), IDLE_TIMEOUT)
    except (ConnectionError, TimeoutError) as exc:
        raise DropError("Connection interrupted while sending.") from exc


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 2)


def _proof(secret: bytes, sender: bytes, receiver: bytes, challenge: bytes) -> bytes:
    return hmac.digest(secret, _MAGIC + b"client-proof\x00" + sender + receiver + challenge, "sha256")


class _Channel:
    def __init__(self, reader, writer, shared: bytes, secret: bytes, sender: bytes, receiver: bytes, challenge: bytes, *, server: bool):
        transcript = _MAGIC + shared + sender + receiver + challenge
        keys = [hashlib.blake2b(transcript + label, key=secret, digest_size=32).digest() for label in (b"sender-to-receiver", b"receiver-to-sender")]
        self.tx = SecretBox(keys[0 if server else 1])
        self.rx = SecretBox(keys[1 if server else 0])
        self.reader, self.writer = reader, writer
        self.tx_seq = self.rx_seq = 0

    async def send(self, kind: bytes, payload: bytes = b"") -> None:
        if len(kind) != 1:
            raise DropError("Invalid message type.")
        encrypted = self.tx.encrypt(kind + payload, self.tx_seq.to_bytes(24, "big")).ciphertext
        self.tx_seq += 1
        await _write_frame(self.writer, encrypted)

    async def recv(self) -> tuple[bytes, bytes]:
        encrypted = await _read_frame(self.reader)
        try:
            plaintext = self.rx.decrypt(encrypted, self.rx_seq.to_bytes(24, "big"))
        except CryptoError as exc:
            raise DropError("Transfer authentication failed.") from exc
        self.rx_seq += 1
        if not plaintext:
            raise DropError("Invalid encrypted message.")
        return plaintext[:1], plaintext[1:]


class Offer:
    def __init__(self, file_path: Path, lifetime: int = 600):
        if type(lifetime) is not int or not 1 <= lifetime <= 86400:
            raise DropError("Invite lifetime must be between 1 and 86400 seconds.")
        self.file_path = Path(file_path).resolve(strict=True)
        info = self.file_path.stat()
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_FILE_SIZE:
            raise DropError("Choose a regular file to send.")
        self.filename = validate_filename(self.file_path.name)
        self.size = info.st_size
        self._initial_stat = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        self._key = PrivateKey.generate()
        self._secret = secrets.token_bytes(32)
        self._lifetime = lifetime
        # Tor can take minutes to bootstrap. Start the lifetime only when the
        # caller first asks for the invite, after its endpoint is ready.
        self.expires = 0
        self.done = asyncio.Event()
        self.succeeded = False
        self.error: str | None = None
        self._used = False
        self._busy = False
        self._connections = 0

    @property
    def sender_fingerprint(self) -> str:
        return fingerprint(bytes(self._key.public_key))

    @property
    def claimed(self) -> bool:
        """An approved request has consumed the invite (even on failure)."""
        return self._used

    def invite(self, host: str, port: int, mode: str) -> str:
        validate_endpoint(host, port, mode)
        if not self.expires:
            self.expires = int(time.time()) + self._lifetime
        if self._used or time.time() >= self.expires:
            raise DropError("This offer is no longer available.")
        return "drop1." + _encode(_json({"host": host, "port": port, "mode": mode, "expires": self.expires,
                                        "secret": _encode(self._secret), "sender": _encode(bytes(self._key.public_key))}))

    async def handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, approve: Approve, progress: Progress | None = None) -> None:
        # No awaits between each admission check and counter/flag mutation.
        if self._connections >= MAX_CONNECTIONS or self._used or time.time() >= self.expires:
            await _close(writer)
            return
        self._connections += 1
        claimed = consumed = False
        try:
            challenge = secrets.token_bytes(32)
            await _write_frame(writer, _MAGIC + challenge)
            hello = await _read_frame(reader, 64, HANDSHAKE_TIMEOUT)
            sender = bytes(self._key.public_key)
            if len(hello) != 64 or not hmac.compare_digest(hello[32:], _proof(self._secret, sender, hello[:32], challenge)):
                raise DropError("Invalid transfer request.")
            receiver = hello[:32]
            try:
                shared = crypto_scalarmult(bytes(self._key), receiver)
            except (CryptoError, RuntimeError) as exc:
                raise DropError("Invalid transfer request.") from exc
            channel = _Channel(reader, writer, shared, self._secret, sender, receiver, challenge, server=True)
            if self._busy or self._used or time.time() >= self.expires:
                await channel.send(b"E", b"Offer unavailable.")
                return
            self._busy = claimed = True
            async with asyncio.timeout(min(APPROVAL_TIMEOUT, max(0, self.expires - time.time()))):
                approved = await approve(fingerprint(receiver))
            if not approved:
                await channel.send(b"E", b"Sender declined the request.")
                return
            if time.time() >= self.expires:
                raise DropError("Invite expired before approval.")
            self._used = consumed = True
            await channel.send(b"M", _json({"name": self.filename, "size": self.size}))
            kind, payload = await channel.recv()
            if kind != b"A" or payload != b"":
                raise DropError("Recipient declined or sent an invalid acceptance.")
            digest = hashlib.sha256()
            sent = 0
            # A pathname can change after Offer's initial stat. Nonblocking
            # open on POSIX prevents a substituted FIFO from hanging before
            # fstat can reject it; no-follow rejects substituted symlinks.
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.file_path, flags)
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != self._initial_stat:
                    raise DropError("The source file changed. Create a new offer.")
                while chunk := source.read(CHUNK_SIZE):
                    sent += len(chunk)
                    if sent > self.size:
                        raise DropError("The source file changed during the transfer.")
                    digest.update(chunk)
                    await channel.send(b"D", chunk)
                    if progress:
                        progress(sent, self.size)
                final_stat = os.fstat(source.fileno())
                if sent != self.size or final_stat.st_mtime_ns != self._initial_stat[3]:
                    raise DropError("The source file changed during the transfer.")
            final = _json({"sha256": digest.hexdigest(), "size": sent})
            await channel.send(b"F", final)
            kind, payload = await channel.recv()
            if kind != b"R" or payload != final:
                raise DropError("Recipient did not confirm the verified file.")
            self.succeeded = True
        except asyncio.CancelledError:
            if consumed:
                self.error = "Transfer cancelled. Create a new offer to retry."
            raise
        except (DropError, OSError, TimeoutError) as exc:
            if consumed:
                self.error = str(exc) if isinstance(exc, DropError) else "Transfer interrupted. Create a new offer to retry."
        finally:
            if claimed:
                self._busy = False
            if consumed:
                self.done.set()
            self._connections -= 1
            await _close(writer)


async def receive(invite: str, destination: Path, connect: Connect, accept: Accept, progress: Progress | None = None, *, identity: Callable[[str], None] | None = None) -> Path:
    invitation = parse_invite(invite)
    destination = Path(destination).resolve(strict=True)
    if not destination.is_dir():
        raise DropError("The destination must be an existing directory.")
    writer = None
    partial: Path | None = None
    key = PrivateKey.generate()
    receiver = bytes(key.public_key)
    if identity:
        identity(fingerprint(receiver))
    try:
        async with asyncio.timeout(IDLE_TIMEOUT):
            reader, writer = await connect(invitation.host, invitation.port, invitation.mode)
        challenge_frame = await _read_frame(reader, len(_MAGIC) + 32, HANDSHAKE_TIMEOUT)
        if len(challenge_frame) != len(_MAGIC) + 32 or not challenge_frame.startswith(_MAGIC):
            raise DropError("Invalid sender handshake.")
        challenge = challenge_frame[len(_MAGIC):]
        await _write_frame(writer, receiver + _proof(invitation.secret, invitation.sender_key, receiver, challenge))
        try:
            shared = crypto_scalarmult(bytes(key), invitation.sender_key)
        except (CryptoError, RuntimeError) as exc:
            raise DropError("Invalid sender identity.") from exc
        channel = _Channel(reader, writer, shared, invitation.secret, invitation.sender_key, receiver, challenge, server=False)
        kind, payload = await channel.recv()
        if kind == b"E":
            raise DropError("Sender declined the request or the offer is unavailable.")
        if kind != b"M":
            raise DropError("Invalid file metadata.")
        meta = _unjson(payload)
        if set(meta) != {"name", "size"} or type(meta["size"]) is not int or not 0 <= meta["size"] <= MAX_FILE_SIZE:
            raise DropError("Invalid file metadata.")
        name = validate_filename(meta["name"])
        final_path = destination / name
        if os.path.lexists(final_path):
            raise DropError("A file with this name already exists in the destination.")
        async with asyncio.timeout(APPROVAL_TIMEOUT):
            accepted = await accept(name, meta["size"], fingerprint(invitation.sender_key))
        if not accepted:
            await channel.send(b"X")
            raise DropError("Transfer declined.")
        fd, temporary_name = tempfile.mkstemp(prefix=".den-drop-", suffix=".part", dir=destination)
        partial = Path(temporary_name)
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(fd, "wb") as output:
            await channel.send(b"A")
            while True:
                kind, payload = await channel.recv()
                if kind == b"D":
                    if not 1 <= len(payload) <= CHUNK_SIZE or total + len(payload) > meta["size"]:
                        raise DropError("Invalid file size or chunk.")
                    output.write(payload)
                    digest.update(payload)
                    total += len(payload)
                    if progress:
                        progress(total, meta["size"])
                elif kind == b"F":
                    final = _json({"sha256": digest.hexdigest(), "size": total})
                    if payload != final or total != meta["size"]:
                        raise DropError("The received file failed integrity verification.")
                    output.flush()
                    os.fsync(output.fileno())
                    break
                else:
                    raise DropError("Unexpected transfer message.")
        # Windows rename refuses replacement; POSIX link provides no-clobber
        # publication. Keep both names in the same directory/filesystem.
        if os.name == "nt":
            os.rename(partial, final_path)
            partial = None
        else:
            os.link(partial, final_path)
            partial.unlink()
            partial = None
        # A lost receipt cannot undo successful local delivery. The sender will
        # report unconfirmed completion; the receiver keeps the verified file.
        try:
            await channel.send(b"R", final)
        except (DropError, OSError):
            pass
        return final_path
    except TimeoutError as exc:
        raise DropError("Transfer timed out.") from exc
    except FileExistsError as exc:
        raise DropError("A file with this name already exists in the destination.") from exc
    except OSError as exc:
        raise DropError("Network or file operation failed; check connectivity, permissions, and disk space.") from exc
    finally:
        if partial is not None:
            with contextlib.suppress(OSError):
                partial.unlink()
        if writer is not None:
            await _close(writer)
