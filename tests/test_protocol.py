import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import os
from pathlib import Path
import struct
import time

import pytest
from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey

from den_drop import protocol as p


async def yes(*args):
    return True


async def no(*args):
    return False


async def direct(host, port, mode):
    assert mode == "lan"
    return await asyncio.open_connection(host, port)


@asynccontextmanager
async def serving(offer, approve=yes, handler=None):
    tasks = set()

    def connected(reader, writer):
        task = asyncio.create_task(handler(reader, writer) if handler else offer.handler(reader, writer, approve))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    server = await asyncio.start_server(connected, "127.0.0.1", 0)
    try:
        yield offer.invite("127.0.0.1", server.sockets[0].getsockname()[1], "lan")
    finally:
        server.close()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await server.wait_closed()


@pytest.fixture
def paths(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    file = source / "sample.bin"
    file.write_bytes(os.urandom(p.CHUNK_SIZE * 2 + 7))
    return file, destination


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [0, 1, p.CHUNK_SIZE, p.CHUNK_SIZE * 2 + 7])
async def test_complete_verified_transfer(paths, size):
    file, destination = paths
    data = os.urandom(size)
    file.write_bytes(data)
    offer = p.Offer(file)
    identities, progress, metadata = [], [], []

    async def accept(name, total, sender):
        metadata.append((name, total, sender))
        return True

    async with serving(offer) as invite:
        result = await p.receive(invite, destination, direct, accept, lambda n, total: progress.append((n, total)), identity=identities.append)
        await asyncio.wait_for(offer.done.wait(), 2)
        assert offer.succeeded and offer.error is None
    assert result.read_bytes() == data
    assert metadata == [(file.name, size, offer.sender_fingerprint)]
    assert len(identities) == 1 and len(identities[0]) == 16
    assert not list(destination.glob("*.part"))
    if size:
        assert progress[-1] == (size, size)


@pytest.mark.parametrize("name", ["../x", "a/b", "a\\b", "C:thing", "a\x00b", "a\nb", "a\x1bb", "..", ".", "CON", "com1.txt", "LPT²", "x.", "x ", "a\u202eb", "\ud800", "a" * 241, ""])
def test_unsafe_filename_rejected(name):
    with pytest.raises(p.DropError):
        p.validate_filename(name)


def test_filename_unicode_allowed():
    assert p.validate_filename("notes-café.txt") == "notes-café.txt"


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "0.0.0.0", "169.254.1.2", "100.64.0.1", "192.0.2.1", "224.1.1.1", "192.168.001.1", "fc00::1%eth0"])
def test_lan_only_private_canonical_numeric_hosts(host):
    with pytest.raises(p.DropError):
        p.validate_endpoint(host, 1234, "lan")


def test_onion_checksum_validation():
    key = os.urandom(32)
    raw = key + hashlib.sha3_256(b".onion checksum" + key + b"\x03").digest()[:2] + b"\x03"
    onion = base64.b32encode(raw).decode().lower() + ".onion"
    p.validate_endpoint(onion, 1234, "tor")
    with pytest.raises(p.DropError):
        p.validate_endpoint("a" * 56 + ".onion", 1234, "tor")


def test_invite_strict_roundtrip_and_no_secrets_in_repr(paths):
    offer = p.Offer(paths[0])
    assert offer.expires == 0
    invite = offer.invite("127.0.0.1", 1234, "lan")
    value = p.parse_invite(invite)
    assert value.host == "127.0.0.1" and value.port == 1234
    assert value.expires == offer.expires
    assert p._encode(value.secret) not in repr(value)
    assert invite == offer.invite("127.0.0.1", 1234, "lan")
    for invalid in (invite + "=", " " + invite, invite + "\n", "drop1." + "A" * 4096, "hush1." + invite[6:]):
        with pytest.raises(p.DropError):
            p.parse_invite(invalid)


@pytest.mark.parametrize("change", [{"expires": 0}, {"expires": True}, {"expires": int(time.time()) + 999999}, {"port": True}, {"secret": "AAAA"}, {"sender": "AAAA"}, {"extra": 1}])
def test_invalid_invite_fields(paths, change):
    invite = p.Offer(paths[0]).invite("127.0.0.1", 1234, "lan")
    data = p._unjson(p._decode(invite[6:]))
    data.update(change)
    with pytest.raises(p.DropError):
        p.parse_invite("drop1." + p._encode(p._json(data)))


@pytest.mark.asyncio
async def test_declined_request_does_not_consume_offer(paths):
    file, destination = paths
    offer = p.Offer(file)
    count = 0

    async def approve(identity):
        nonlocal count
        count += 1
        return count == 2

    async with serving(offer, approve) as invite:
        with pytest.raises(p.DropError, match="declined"):
            await p.receive(invite, destination, direct, yes)
        assert not offer.done.is_set()
        result = await p.receive(invite, destination, direct, yes)
        assert result.read_bytes() == file.read_bytes()
        await asyncio.wait_for(offer.done.wait(), 2)
        assert offer.succeeded


@pytest.mark.asyncio
async def test_invalid_auth_does_not_consume_invite(paths):
    file, destination = paths
    offer = p.Offer(file)
    async with serving(offer) as invite:
        info = p.parse_invite(invite)
        reader, writer = await direct(info.host, info.port, info.mode)
        await p._read_frame(reader)
        await p._write_frame(writer, os.urandom(64))
        assert await asyncio.wait_for(reader.read(), 2) == b""
        await p._close(writer)
        assert not offer.done.is_set()
        assert (await p.receive(invite, destination, direct, yes)).read_bytes() == file.read_bytes()


@pytest.mark.asyncio
async def test_receiver_decline_consumes_approved_offer(paths):
    file, destination = paths
    offer = p.Offer(file)
    async with serving(offer) as invite:
        with pytest.raises(p.DropError, match="declined"):
            await p.receive(invite, destination, direct, no)
        await asyncio.wait_for(offer.done.wait(), 2)
        assert not offer.succeeded
        with pytest.raises(p.DropError):
            await p.receive(invite, destination, direct, yes)
    assert list(destination.iterdir()) == []


@pytest.mark.asyncio
async def test_second_recipient_cannot_transfer(paths):
    file, destination = paths
    offer = p.Offer(file)
    async with serving(offer) as invite:
        await p.receive(invite, destination, direct, yes)
        await asyncio.wait_for(offer.done.wait(), 2)
        (destination / file.name).unlink()
        with pytest.raises(p.DropError):
            await p.receive(invite, destination, direct, yes)
    assert list(destination.iterdir()) == []


@pytest.mark.asyncio
async def test_existing_file_never_overwritten(paths):
    file, destination = paths
    existing = destination / file.name
    existing.write_bytes(b"precious")
    async with serving(p.Offer(file)) as invite:
        with pytest.raises(p.DropError, match="already exists"):
            await p.receive(invite, destination, direct, yes)
    assert existing.read_bytes() == b"precious"
    assert list(destination.iterdir()) == [existing]


@pytest.mark.asyncio
async def test_collision_created_after_accept_not_overwritten(paths):
    file, destination = paths
    existing = destination / file.name

    async def accept(*args):
        existing.write_bytes(b"precious")
        return True

    async with serving(p.Offer(file)) as invite:
        with pytest.raises(p.DropError, match="already exists"):
            await p.receive(invite, destination, direct, accept)
    assert existing.read_bytes() == b"precious"
    assert list(destination.iterdir()) == [existing]


@pytest.mark.asyncio
async def test_changed_source_refused(paths):
    file, destination = paths
    offer = p.Offer(file)
    file.write_bytes(b"changed")
    async with serving(offer) as invite:
        with pytest.raises(p.DropError):
            await p.receive(invite, destination, direct, yes)
        await asyncio.wait_for(offer.done.wait(), 2)
        assert not offer.succeeded and "changed" in offer.error
    assert list(destination.iterdir()) == []


async def malicious_channel(offer, reader, writer):
    challenge = os.urandom(32)
    await p._write_frame(writer, p._MAGIC + challenge)
    hello = await p._read_frame(reader)
    sender = bytes(offer._key.public_key)
    assert hello[32:] == p._proof(offer._secret, sender, hello[:32], challenge)
    shared = crypto_scalarmult(bytes(offer._key), hello[:32])
    return p._Channel(reader, writer, shared, offer._secret, sender, hello[:32], challenge, server=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["truncate", "corrupt", "replay", "bad_hash", "extra_data", "bad_filename", "early_final"])
async def test_malicious_or_broken_sender_cleans_partial(paths, attack):
    file, destination = paths
    offer = p.Offer(file)

    async def handler(reader, writer):
        try:
            channel = await malicious_channel(offer, reader, writer)
            name = "../escape.bin" if attack == "bad_filename" else file.name
            await channel.send(b"M", p._json({"name": name, "size": 4}))
            if attack == "bad_filename":
                return
            await channel.recv()
            if attack == "corrupt":
                await p._write_frame(writer, os.urandom(40))
            elif attack == "replay":
                await channel.send(b"D", b"a")
                channel.tx_seq -= 1
                await channel.send(b"D", b"a")
            elif attack == "extra_data":
                await channel.send(b"D", b"12345")
            elif attack == "early_final":
                await channel.send(b"F", p._json({"sha256": hashlib.sha256(b"").hexdigest(), "size": 0}))
            else:
                await channel.send(b"D", b"1234")
                if attack == "bad_hash":
                    await channel.send(b"F", p._json({"sha256": "0" * 64, "size": 4}))
        finally:
            await p._close(writer)

    async with serving(offer, handler=handler) as invite:
        with pytest.raises(p.DropError):
            await p.receive(invite, destination, direct, yes)
    assert list(destination.iterdir()) == []
    assert not (destination.parent / "escape.bin").exists()


@pytest.mark.asyncio
async def test_cancellation_removes_partial(paths):
    file, destination = paths
    offer = p.Offer(file)
    partial_written = asyncio.Event()

    async def handler(reader, writer):
        try:
            channel = await malicious_channel(offer, reader, writer)
            await channel.send(b"M", p._json({"name": file.name, "size": 100}))
            await channel.recv()
            await channel.send(b"D", b"a")
            await asyncio.Event().wait()
        finally:
            await p._close(writer)

    async with serving(offer, handler=handler) as invite:
        task = asyncio.create_task(p.receive(invite, destination, direct, yes, lambda *args: partial_written.set()))
        await asyncio.wait_for(partial_written.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert list(destination.iterdir()) == []


@pytest.mark.asyncio
async def test_frame_bounds_checked_before_body_read():
    for size in (0, p.MAX_FRAME + 1, 2**32 - 1):
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("!I", size))
        with pytest.raises(p.DropError, match="oversized"):
            await p._read_frame(reader)


@pytest.mark.asyncio
async def test_approval_timeout_does_not_consume(paths, monkeypatch):
    file, destination = paths
    offer = p.Offer(file)
    monkeypatch.setattr(p, "APPROVAL_TIMEOUT", 0.01)

    async def stalled(*args):
        await asyncio.Event().wait()

    async with serving(offer, stalled) as invite:
        with pytest.raises(p.DropError):
            await p.receive(invite, destination, direct, yes)
        assert not offer.done.is_set()
