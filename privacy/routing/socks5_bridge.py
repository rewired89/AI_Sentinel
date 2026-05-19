"""
HTTP-CONNECT to SOCKS5 bridge.

mitmproxy's --mode upstream only accepts http:// proxies.
This bridge translates HTTP CONNECT into SOCKS5 so mitmproxy can chain
through i2pd (or any SOCKS5 backend) without extra dependencies.

  mitmproxy (8877) --http-upstream--> bridge (8878) --socks5--> i2pd (4447)
"""
import asyncio
import struct

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 8878

_socks5_host = "127.0.0.1"
_socks5_port = 4447


async def _socks5_connect(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(_socks5_host, _socks5_port)

    # Greeting — request no-auth method
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    if resp[1] != 0x00:
        writer.close()
        raise ConnectionError(f"SOCKS5 auth rejected: {resp.hex()}")

    # CONNECT with ATYP=domain so i2pd resolves the name inside I2P (no DNS leak)
    host_b = host.encode()
    writer.write(
        b"\x05\x01\x00\x03"
        + bytes([len(host_b)])
        + host_b
        + struct.pack(">H", port)
    )
    await writer.drain()

    # Response — length varies by address type
    hdr = await reader.readexactly(4)   # VER REP RSV ATYP
    if hdr[1] != 0x00:
        writer.close()
        raise ConnectionError(f"SOCKS5 CONNECT refused: rep={hdr[1]:#04x}")
    atyp = hdr[3]
    if atyp == 0x01:       # IPv4
        await reader.readexactly(4 + 2)
    elif atyp == 0x03:     # domain
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    elif atyp == 0x04:     # IPv6
        await reader.readexactly(16 + 2)

    return reader, writer


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except Exception:
        pass
    finally:
        try:
            dst.close()
            await dst.wait_closed()
        except Exception:
            pass


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await reader.readline()
        if not line:
            return
        parts = line.decode(errors="replace").split(None, 2)
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await writer.drain()
            return

        # Drain remaining request headers
        while True:
            hdr = await reader.readline()
            if hdr in (b"\r\n", b"\n", b""):
                break

        target = parts[1]
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s.isdigit() else 443

        try:
            s_reader, s_writer = await _socks5_connect(host, port)
        except Exception as exc:
            writer.write(
                f"HTTP/1.1 502 Bad Gateway\r\nX-Bridge-Error: {exc}\r\n\r\n".encode()
            )
            await writer.drain()
            return

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        await asyncio.gather(_pipe(reader, s_writer), _pipe(s_reader, writer))
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _serve(
    bridge_port: int, socks5_host: str, socks5_port: int
) -> None:
    global _socks5_host, _socks5_port
    _socks5_host = socks5_host
    _socks5_port = socks5_port
    server = await asyncio.start_server(_handle, BRIDGE_HOST, bridge_port)
    async with server:
        print(
            f"[bridge] HTTP→SOCKS5 on {BRIDGE_HOST}:{bridge_port}"
            f" → {socks5_host}:{socks5_port}"
        )
        await server.serve_forever()


def run(
    bridge_port: int = BRIDGE_PORT,
    socks5_host: str = "127.0.0.1",
    socks5_port: int = 4447,
) -> None:
    """Blocking — intended to be called from a daemon thread."""
    asyncio.run(_serve(bridge_port, socks5_host, socks5_port))
