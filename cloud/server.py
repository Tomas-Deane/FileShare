#!/usr/bin/env python3
import asyncio
import logging
import os

from models import init_db, UserDB
from utils import read_json, send_response
from handlers import handle_message

LOG_FILE = os.path.join(os.path.dirname(__file__), 'server_debug.log')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

db = None

async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    logging.info(f"Connection from {peer}")
    session = {'username': None, 'challenge': None}

    try:
        while True:
            data = await read_json(reader)
            if data is None:
                break
            try:
                await handle_message(data, session, writer, db)
            except Exception as e:
                logging.exception("Exception processing client data")
                await send_response(writer, {'status':'error', 'error': str(e)})
    except Exception as e:
        logging.exception(f"Error in connection handler for {peer}")
    finally:
        writer.close()
        await writer.wait_closed()
        logging.info(f"Closed connection {peer}")

async def main():
    global db
    init_db()
    db = UserDB()
    server = await asyncio.start_server(handle_client, '0.0.0.0', 3210)
    addr = server.sockets[0].getsockname()
    logging.info(f"Serving on {addr}")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())