import json
from typing import Dict


def build_message(sender: str, payload: str, integrity: str) -> str:
    message: Dict[str, str] = {
        "sender": sender,
        "payload": payload,
        "integrity": integrity
    }
    return json.dumps(message)


def parse_message(message_str: str) -> Dict[str, str]:
    return json.loads(message_str)
