import asyncio
from pathlib import Path

import pytest

from den_drop import cli
from den_drop.protocol import Offer


def test_terminal_controls_removed():
    assert "\x1b" not in cli.display("bad\x1b[2Jfile")
    assert "\u202e" not in cli.display("bad\u202efile")
    assert cli.display("report.pdf") == "report.pdf"


@pytest.mark.parametrize("arguments", [
    ["send", "file", "--host", "127.0.0.1"],
    ["send", "file", "--lan"],
    ["send", "file", "--lan", "--host", "0.0.0.0"],
    ["send", "file", "--lan", "--host", "8.8.8.8"],
    ["send", "file", "--lan", "--host", "example.org"],
    ["send", "file", "--expires", "0"],
])
async def test_invalid_cli_options_fail_before_listening(arguments, monkeypatch):
    def forbid(*a, **k):
        pytest.fail("Must validate options before opening a listener")

    monkeypatch.setattr(cli.asyncio, "start_server", forbid)
    with pytest.raises(Exception):
        await cli.send_file(cli.parser().parse_args(arguments))


async def test_lan_invite_requires_explicit_lan_option(tmp_path, monkeypatch):
    source = tmp_path / "example.bin"
    source.write_bytes(b"example")
    token = Offer(source).invite("127.0.0.1", 12345, "lan")

    class Input:
        async def prompt_async(self, *a, **k):
            return token

    def forbid(*a, **k):
        pytest.fail("Mode mismatch must fail before Tor starts")

    monkeypatch.setattr(cli, "PromptSession", Input)
    monkeypatch.setattr(cli, "ManagedTor", forbid)
    with pytest.raises(ValueError, match="mode does not match"):
        await cli.receive_file(cli.parser().parse_args(["receive", "--output", str(tmp_path)]))


@pytest.mark.parametrize("slow_accept", [False, True])
async def test_send_receive_cli_flow(tmp_path, monkeypatch, capsys, slow_accept):
    source = tmp_path / "report.bin"
    data = bytes(range(256)) * 1024
    source.write_bytes(data)
    output = tmp_path / "output"
    output.mkdir()
    ready = asyncio.Event()
    token = ""

    class CapturedOffer(Offer):
        def invite(self, *a, **k):
            nonlocal token
            token = super().invite(*a, **k)
            ready.set()
            return token

    class Input:
        async def prompt_async(self, prompt, **kwargs):
            if "Secret invite" in prompt:
                await ready.wait()
                assert kwargs.get("is_password") is True
                return token
            if "Accept this file" in prompt and slow_accept:
                # Approval has consumed the invite. Its deadline must not
                # terminate an accepted transfer still awaiting local consent.
                await asyncio.sleep(2.1)
            return "yes"

    monkeypatch.setattr(cli, "Offer", CapturedOffer)
    monkeypatch.setattr(cli, "PromptSession", Input)
    args = cli.parser().parse_args(["send", str(source), "--lan", "--host", "127.0.0.1",
                                   "--expires", "2" if slow_accept else "20"])
    sender = asyncio.create_task(cli.send_file(args))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        await cli.receive_file(cli.parser().parse_args([
            "receive", "--lan", "--output", str(output)]))
        await asyncio.wait_for(sender, 5)
    finally:
        sender.cancel()
        await asyncio.gather(sender, return_exceptions=True)
    assert (output / source.name).read_bytes() == data
    assert len(list(output.iterdir())) == 1
    text = capsys.readouterr().out
    assert "Delivered." in text
    assert "Verified and saved" in text
    assert "Your recipient code:" in text


async def test_unused_invite_expires_and_listener_closes(tmp_path, monkeypatch):
    source = tmp_path / "example.bin"
    source.write_bytes(b"example")
    monkeypatch.setattr(cli, "PromptSession", lambda: object())
    args = cli.parser().parse_args(["send", str(source), "--lan", "--host", "127.0.0.1",
                                   "--expires", "1"])
    with pytest.raises(TimeoutError, match="Invite expired"):
        await asyncio.wait_for(cli.send_file(args), 5)


async def test_demo(capsys):
    await cli.demo()
    assert "Demo complete" in capsys.readouterr().out


async def test_cancel_sender_with_pending_approval_closes_connections(tmp_path):
    source = tmp_path / "pending.bin"
    source.write_bytes(b"not approved")
    destination = tmp_path / "output"
    destination.mkdir()
    offer = Offer(source)
    pending = asyncio.Event()

    async def approve(_fingerprint):
        pending.set()
        await asyncio.Event().wait()

    async def accept(*_):
        pytest.fail("Metadata must not be sent before approval")

    receiver = None

    async def host():
        nonlocal receiver
        async with cli.listener(offer, "127.0.0.1", 0, approve) as server:
            token = offer.invite("127.0.0.1", server.sockets[0].getsockname()[1], "lan")
            receiver = asyncio.create_task(cli.receive(token, destination,
                                                       cli.direct_connection, accept))
            await asyncio.Event().wait()

    sender = asyncio.create_task(host())
    try:
        await asyncio.wait_for(pending.wait(), 5)
        sender.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(sender, 5)
        with pytest.raises(Exception):
            await asyncio.wait_for(receiver, 5)
        assert list(destination.iterdir()) == []
    finally:
        sender.cancel()
        if receiver:
            receiver.cancel()
        await asyncio.gather(sender, *([receiver] if receiver else []), return_exceptions=True)


async def test_sender_eof_stops_host(tmp_path, monkeypatch):
    source = tmp_path / "pending.bin"
    source.write_bytes(b"not approved")
    destination = tmp_path / "output"
    destination.mkdir()
    ready = asyncio.Event()
    token = ""

    class CapturedOffer(Offer):
        def invite(self, *a, **k):
            nonlocal token
            token = super().invite(*a, **k)
            ready.set()
            return token

    class Input:
        async def prompt_async(self, *a, **k):
            raise EOFError

    async def accept(*_):
        pytest.fail("Closed input cannot authorize a transfer")

    monkeypatch.setattr(cli, "Offer", CapturedOffer)
    monkeypatch.setattr(cli, "PromptSession", Input)
    args = cli.parser().parse_args(["send", str(source), "--lan", "--host", "127.0.0.1"])
    sender = asyncio.create_task(cli.send_file(args))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        with pytest.raises(Exception):
            await cli.receive(token, destination, cli.direct_connection, accept)
        with pytest.raises(RuntimeError, match="Terminal input closed"):
            await asyncio.wait_for(sender, 5)
    finally:
        sender.cancel()
        await asyncio.gather(sender, return_exceptions=True)
