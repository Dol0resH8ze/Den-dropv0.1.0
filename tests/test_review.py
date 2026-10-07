"""Independent adversarial checks for handshake, admission, and final receipts."""

import asyncio
from contextlib import asynccontextmanager
import os
import time

from nacl.public import PrivateKey
import pytest

from den_drop import protocol as p


async def yes(*_args):
    return True


async def direct(host, port, mode):
    assert mode == "lan"
    return await asyncio.open_connection(host, port)


@asynccontextmanager
async def host(offer, approve=yes):
    tasks = set()

    def connected(reader, writer):
        task = asyncio.create_task(offer.handler(reader, writer, approve))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    server = await asyncio.start_server(connected, "127.0.0.1", 0)
    try:
        yield offer.invite("127.0.0.1", server.sockets[0].getsockname()[1], "lan")
    finally:
        server.close()
        await server.wait_closed()
        pending = list(tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


@pytest.fixture
def transfer_paths(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"private file contents\n")
    destination = tmp_path / "received"
    destination.mkdir()
    return source, destination


async def test_hello_replay_from_other_connection_cannot_request_approval(transfer_paths):
    source, destination = transfer_paths
    offer = p.Offer(source)
    approvals = []

    async def approve(identity):
        approvals.append(identity)
        return True

    async with host(offer, approve) as invite:
        info = p.parse_invite(invite)
        reader1, writer1 = await direct(info.host, info.port, info.mode)
        challenge1 = (await p._read_frame(reader1))[len(p._MAGIC):]
        receiver = bytes(PrivateKey.generate().public_key)
        captured_hello = receiver + p._proof(info.secret, info.sender_key, receiver, challenge1)
        await p._close(writer1)

        reader2, writer2 = await direct(info.host, info.port, info.mode)
        challenge2 = (await p._read_frame(reader2))[len(p._MAGIC):]
        assert challenge1 != challenge2
        await p._write_frame(writer2, captured_hello)
        assert await asyncio.wait_for(reader2.read(), 2) == b""
        await p._close(writer2)
        assert approvals == []
        assert not offer.done.is_set()

        result = await p.receive(invite, destination, direct, yes)
        assert result.read_bytes() == source.read_bytes()
        await asyncio.wait_for(offer.done.wait(), 2)
        assert len(approvals) == 1 and offer.succeeded


def test_directional_and_fresh_handshake_keys_prevent_nonce_zero_reuse():
    shared, secret, sender, receiver, challenge = (os.urandom(32) for _ in range(5))
    server = p._Channel(None, None, shared, secret, sender, receiver, challenge, server=True)
    client = p._Channel(None, None, shared, secret, sender, receiver, challenge, server=False)
    fresh = p._Channel(None, None, shared, secret, sender, receiver, os.urandom(32), server=True)
    nonce = bytes(24)
    message = b"identical first frame"
    encrypted = server.tx.encrypt(message, nonce).ciphertext
    assert client.rx.decrypt(encrypted, nonce) == message
    assert client.tx.encrypt(message, nonce).ciphertext != encrypted
    assert fresh.tx.encrypt(message, nonce).ciphertext != encrypted


async def test_concurrent_request_never_opens_second_approval(transfer_paths):
    source, destination = transfer_paths
    offer = p.Offer(source)
    requested, release = asyncio.Event(), asyncio.Event()
    approvals = []

    async def approve(identity):
        approvals.append(identity)
        requested.set()
        await release.wait()
        return True

    async with host(offer, approve) as invite:
        first = asyncio.create_task(p.receive(invite, destination, direct, yes))
        try:
            await asyncio.wait_for(requested.wait(), 2)
            with pytest.raises(p.DropError, match="unavailable"):
                await p.receive(invite, destination, direct, yes)
            assert len(approvals) == 1
            release.set()
            result = await asyncio.wait_for(first, 2)
            await asyncio.wait_for(offer.done.wait(), 2)
            assert result.read_bytes() == source.read_bytes()
            assert offer.succeeded
        finally:
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)


async def test_expiry_during_approval_never_sends_metadata(transfer_paths):
    source, destination = transfer_paths
    offer = p.Offer(source)
    accepted = []

    async def approve(_identity):
        offer.expires = int(time.time()) - 1
        return True

    async def accept(*metadata):
        accepted.append(metadata)
        return True

    async with host(offer, approve) as invite:
        with pytest.raises(p.DropError, match="closed"):
            await p.receive(invite, destination, direct, accept)
    assert accepted == []
    assert list(destination.iterdir()) == []
    assert not offer._used


async def test_lost_receipt_preserves_verified_receiver_file(transfer_paths, monkeypatch):
    source, destination = transfer_paths
    offer = p.Offer(source)
    original_send = p._Channel.send

    async def broken_receipt(self, kind, payload=b""):
        if kind == b"R":
            raise OSError("simulated lost receipt")
        return await original_send(self, kind, payload)

    monkeypatch.setattr(p._Channel, "send", broken_receipt)
    async with host(offer) as invite:
        result = await p.receive(invite, destination, direct, yes)
        await asyncio.wait_for(offer.done.wait(), 2)
        assert not offer.succeeded
        assert offer._used
    assert result.read_bytes() == source.read_bytes()
    assert list(destination.iterdir()) == [result]
