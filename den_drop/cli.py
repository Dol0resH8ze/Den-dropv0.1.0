"""One-command sender hosting and receiver interface."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
import hashlib
from pathlib import Path
import sys
import tempfile
import time
import unicodedata

from prompt_toolkit import PromptSession

from . import __version__
from .protocol import Offer, parse_invite, receive, validate_endpoint
from .tor import ManagedTor


def display(value: object) -> str:
    """Do not let a filename, path, or error inject terminal control codes."""
    return "".join(c if not unicodedata.category(c).startswith("C") else "?"
                   for c in str(value))


def size_text(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    raise AssertionError("unreachable")


class Progress:
    def __init__(self, label: str):
        self.label = label
        self.last = 0.0
        self.started = False

    def __call__(self, current: int, total: int) -> None:
        now = time.monotonic()
        if now - self.last < 0.25 and current != total:
            return
        self.last = now
        self.started = True
        ratio = current / total if total else 1.0
        cells = min(24, int(ratio * 24))
        bar = "#" * cells + "-" * (24 - cells)
        print(f"\r{self.label} [{bar}] {ratio:6.1%}  "
              f"{size_text(current)} / {size_text(total)}", end="", flush=True)

    def finish(self) -> None:
        if self.started:
            print()
            self.started = False


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="den-drop", description="Private file handoffs. No accounts. Self-hosted.")
    p.add_argument("--version", action="version", version=f"Den Drop {__version__}")
    commands = p.add_subparsers(dest="command", required=True)
    send = commands.add_parser("send", help="Host one file and create a temporary invite")
    send.add_argument("file", type=Path)
    send.add_argument("--expires", type=int, default=600, metavar="SECONDS",
                      help="Time allowed to approve a recipient (default 600, max 86400)")
    send.add_argument("--host", help="Numeric private LAN address; required with --lan")
    send.add_argument("--port", type=int, default=0,
                      help="Local listening port (default: choose an available port)")
    recv = commands.add_parser("receive", help="Paste a hidden invite and receive one file")
    recv.add_argument("--output", type=Path, default=Path.cwd(), metavar="DIRECTORY",
                      help="Existing destination directory (default: current directory)")
    for command in (send, recv):
        command.add_argument("--lan", action="store_true",
                             help="Explicit direct LAN mode; exposes IP addresses, bypasses Tor")
        command.add_argument("--tor-exe", type=Path, metavar="PATH",
                             help="Installed Tor executable (otherwise discovered automatically)")
    commands.add_parser("demo", help="Test a local encrypted transfer; no Tor or network anonymity")
    return p


async def confirm(session: PromptSession, text: str) -> bool:
    answer = await session.prompt_async(text + " [y/N] ")
    return answer.strip().lower() in ("y", "yes")


@asynccontextmanager
async def listener(offer: Offer, host: str, port: int, approve, progress=None):
    tasks: set[asyncio.Task] = set()

    async def handle(reader, writer):
        try:
            await offer.handler(reader, writer, approve, progress)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=5)
            except (OSError, TimeoutError):
                pass

    def completed(task):
        tasks.discard(task)
        if not task.cancelled():
            # Peer errors are handled by Offer; never print remote data/tracebacks.
            task.exception()

    def connected(reader, writer):
        if len(tasks) >= 8 or offer.done.is_set():
            writer.close()
            return
        task = asyncio.create_task(handle(reader, writer))
        tasks.add(task)
        task.add_done_callback(completed)

    server = await asyncio.start_server(connected, host=host, port=port)
    try:
        yield server
    finally:
        server.close()
        pending = list(tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        # Python 3.12 waits for accepted connections as well as the listener.
        # Close handler streams before waiting for the server to close.
        await server.wait_closed()


async def direct_connection(host: str, port: int, mode: str):
    if mode != "lan":
        raise ValueError("Direct connections require a LAN invite and --lan.")
    # parse_invite already validated the numeric private/loopback destination.
    async with asyncio.timeout(30):
        return await asyncio.open_connection(host=host, port=port)


async def send_file(args) -> None:
    if not 1 <= args.expires <= 86400:
        raise ValueError("--expires must be between 1 and 86400 seconds.")
    if not 0 <= args.port <= 65535:
        raise ValueError("--port must be between 0 and 65535.")
    if args.lan and not args.host:
        raise ValueError("Use --lan --host YOUR_PRIVATE_LAN_IP (or 127.0.0.1 for a local test).")
    if args.host and not args.lan:
        raise ValueError("--host requires --lan. Tor hosting always binds to loopback.")
    if args.lan and args.tor_exe:
        raise ValueError("--tor-exe cannot be combined with --lan.")
    host = args.host if args.lan else "127.0.0.1"
    if args.lan:
        # Reject hostnames and wildcard/public listeners before opening a socket.
        validate_endpoint(host, args.port or 1, "lan")
    offer = Offer(args.file, lifetime=args.expires)
    session = PromptSession()
    progress = Progress("Sending")

    async def approve(fingerprint: str) -> bool:
        print(f"Recipient requesting this file: {display(fingerprint)}")
        print("Compare this code with the recipient through your private channel.")
        try:
            return await confirm(session, "Approve this recipient?")
        except EOFError:
            offer.error = "Terminal input closed. Handoff cancelled."
            offer.done.set()
            return False

    try:
        async with AsyncExitStack() as stack:
            server = await stack.enter_async_context(
                listener(offer, host, args.port, approve, progress))
            port = server.sockets[0].getsockname()[1]
            mode = "lan" if args.lan else "tor"
            if args.lan:
                print("LAN MODE: direct connection; IP addresses are visible. Tor is disabled.")
            else:
                tor = await stack.enter_async_context(ManagedTor(
                    executable=args.tor_exe, service_port=port, status=print))
                host, port = tor.onion_host, 8765
            token = offer.invite(host, port, mode)
            print(f"Offering: {display(offer.filename)} ({size_text(offer.size)})")
            print(f"Secret invite — share privately; approval expires in {args.expires}s:")
            print(token)
            print("Keep this terminal open. Ctrl+C cancels the handoff.")
            # Once approved, a large transfer may run beyond invite expiry.
            while not offer.done.is_set():
                await asyncio.sleep(0.1)
                if time.time() >= offer.expires and not offer.claimed:
                    raise TimeoutError("Invite expired before a recipient was approved.")
            progress.finish()
            if not offer.succeeded:
                raise RuntimeError(offer.error or "Transfer did not finish. Create a new invite.")
            print("Delivered. The recipient verified and saved the file. Invite consumed.")
    finally:
        progress.finish()


async def receive_file(args) -> None:
    if args.lan and args.tor_exe:
        raise ValueError("--tor-exe cannot be combined with --lan.")
    if not args.output.is_dir():
        raise ValueError("--output must be an existing directory.")
    session = PromptSession()
    token = (await session.prompt_async("Secret invite (hidden): ", is_password=True)).strip()
    invite = parse_invite(token)
    expected_mode = "lan" if args.lan else "tor"
    if invite.mode != expected_mode:
        raise ValueError("Invite mode does not match. Use --lan only for a LAN invite; "
                         "omit it for Tor. No connection was attempted.")
    progress = Progress("Receiving")

    async def accept(filename: str, size: int, fingerprint: str) -> bool:
        print(f"Sender: {display(fingerprint)}")
        print(f"File: {display(filename)} ({size_text(size)})")
        print(f"Save in: {display(args.output.resolve())}")
        return await confirm(session, "Accept this file?")

    try:
        async with AsyncExitStack() as stack:
            if args.lan:
                print("LAN MODE: direct connection; IP addresses are visible. Tor is disabled.")
                connect = direct_connection
            else:
                tor = await stack.enter_async_context(ManagedTor(
                    executable=args.tor_exe, status=print))

                async def connect(host, port, mode):
                    if mode != "tor":
                        raise ValueError("Tor mode requires an onion invite.")
                    return await tor.connect(host, port)

            result = await receive(token, args.output, connect, accept, progress,
                                   identity=lambda fp: print(f"Your recipient code: {display(fp)}"))
            progress.finish()
            print(f"Verified and saved: {display(result)}")
    finally:
        progress.finish()


async def demo() -> None:
    print("Local encrypted demo. Tor is disabled; this does not test anonymity.")
    with tempfile.TemporaryDirectory(prefix="den-drop-demo-") as root:
        directory = Path(root)
        source = directory / "sample.bin"
        payload = bytes(range(256)) * 1024 + b"Den Drop demo\n"
        source.write_bytes(payload)
        output = directory / "received"
        output.mkdir()
        offer = Offer(source)

        async def approve(_fingerprint):
            return True

        async def accept(_name, _size, _fingerprint):
            return True

        async with listener(offer, "127.0.0.1", 0, approve) as server:
            invite = offer.invite("127.0.0.1", server.sockets[0].getsockname()[1], "lan")
            result = await receive(invite, output, direct_connection, accept)
            await asyncio.wait_for(offer.done.wait(), 10)
            if not offer.succeeded or result.read_bytes() != payload:
                raise RuntimeError("Demo failed its end-to-end comparison.")
            print(f"Transferred and verified {size_text(len(payload))}.")
            print(f"SHA-256: {hashlib.sha256(payload).hexdigest()}")
            print("Demo complete. Temporary demo files removed on exit.")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    print("DEN DROP / private file handoffs")
    print("Experimental protocol; not independently audited.")
    try:
        match args.command:
            case "send":
                asyncio.run(send_file(args))
            case "receive":
                asyncio.run(receive_file(args))
            case "demo":
                asyncio.run(demo())
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. The local host and managed Tor process have stopped.")
        return 130
    except Exception as exc:
        # Peer data is never dumped. Protocol/Tor errors use fixed explanations.
        print(f"Error: {display(exc)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
