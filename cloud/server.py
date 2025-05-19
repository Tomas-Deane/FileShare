#!/usr/bin/env python3

import asyncio

async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    print(f"Connection from {peer}")
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            msg = data.decode().rstrip('\n')
            print(f"Received: {msg!r} from {peer}")
            resp = f"Echo: {msg}\n"
            writer.write(resp.encode())
            await writer.drain()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"Closed connection {peer}")

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 12344)
    addr = server.sockets[0].getsockname()
    print(f"Serving on {addr}")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
