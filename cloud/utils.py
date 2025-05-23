#!/usr/bin/env python3
import json
import logging

async def send_response(writer, resp: dict):
    """
    Send a JSON‐encoded response (plus newline) back to the client.
    """
    raw = json.dumps(resp) + '\n' # '\n' is the message delimiter so client doesnt attempt to handle partial messages (TCP is stream)
    logging.debug(f"Sending response: {raw.strip()}")
    writer.write(raw.encode())
    await writer.drain()

async def read_json(reader):
    """
    Read one line at a time, return the first valid JSON object.
    Ignore any lines that aren't valid JSON (e.g. HTTP probes).
    """
    while True:
        raw = await reader.readline()
        if not raw:
            return None
        logging.debug(f"Received raw line: {raw.strip()!r}")
        try:
            data = json.loads(raw.decode())
            logging.debug(f"Parsed JSON data: {data}")
            return data
        except json.JSONDecodeError:
            logging.warning(f"Ignoring non-JSON line: {raw.strip()!r}")
            # skip this line and read the next
            continue