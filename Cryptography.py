import os
import time
from Constans import NONCE_SIZE, TS_SIZE, WINDOW
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

class Cryptography:
    def __init__(self, key):

        self.chacha = ChaCha20Poly1305(key)
        self.seen = {}

    def encrypt(self, packet):

        nonce = os.urandom(NONCE_SIZE)
        ts_bytes = int(time.time()).to_bytes(TS_SIZE, "big")
        return nonce + ts_bytes + self.chacha.encrypt(nonce, packet, ts_bytes)

    def decrypt(self, packet):

        if len(packet) < NONCE_SIZE + TS_SIZE:
            raise RuntimeError()

        nonce = packet[:NONCE_SIZE]
        ts_bytes = packet[NONCE_SIZE:NONCE_SIZE + TS_SIZE]
        cyphered = packet[NONCE_SIZE + TS_SIZE:]
        timestamp = int.from_bytes(ts_bytes, "big")
        now = int(time.time())

        if abs(now - timestamp) > WINDOW:
            print("stale packet")
            raise RuntimeError()

        self.seen = {n: t for n, t in self.seen.items() if now - t <= WINDOW}

        if nonce in self.seen:
            print("seen packet")
            raise RuntimeError()

        try:
            decyphered = self.chacha.decrypt(nonce, cyphered, ts_bytes).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError):
            print("invalid tag")
            raise RuntimeError()

        self.seen[nonce] = timestamp
        return decyphered