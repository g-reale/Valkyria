import json
import socket
import logging
from Constans import BUFFER_SIZE, PORT_MAX, TIMEOUT, HOST
from base64 import b64decode
from threading import Thread, Event
from Types import OneUseData, LimitedInteger
from Cryptography import Cryptography

log = logging.getLogger("valkyria.server")

class Server:

    def __init__(self,config_path):

        # Let exceptions break the server on config
        with open(config_path, "r", encoding="utf-8") as file:
            configs = json.load(file)
        self.allowed_users      = {user for user in configs["valkyria_users"]}
        self.allowed_targets    = {target for target in configs["valkyria_targets"]}
        self.valkyria_key       = b64decode(configs["valkyria_key"])
        self.valkyria_port      = LimitedInteger(configs["valkyria_port"],0,PORT_MAX)

        self.dead = Event()
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.socket.bind((HOST,self.valkyria_port.asNumber()))
        self.socket.settimeout(TIMEOUT)
        self.targets = {target : None for target in self.allowed_targets}
        self.users = {user : None for user in self.allowed_users}
        self.rx_thread = None
        self.cryptography = Cryptography(self.valkyria_key)

        log.info("bound to UDP port %d (%d users, %d targets allowed)",
                 self.valkyria_port.asNumber(),
                 len(self.allowed_users), len(self.allowed_targets))

    def rx(self): # process one client at a time, single threaded server
        log.debug("rx thread started")

        while not self.dead.is_set():

            try:
                raw, source = self.socket.recvfrom(BUFFER_SIZE)
            except (socket.timeout, ConnectionResetError):
                continue

            ip = source[0]
            log.debug("packet from %s", ip)

            try:
                decyphered = self.cryptography.decrypt(raw)
                packet = tuple(word for word in decyphered.split("\0"))
                response = None
            except RuntimeError:
                log.debug("dropped invalid packet from %s", ip)
                continue

            match packet:

                case ("client", user, target):

                    if user not in self.allowed_users:
                        log.warning("client packet from user not allowed: %r", user)
                        continue

                    if target not in self.allowed_targets:
                        log.warning("client packet for target not allowed: %r", target)
                        continue

                    if self.users[user] != ip:
                        log.info("user %s address changed", user)
                        log.debug("user %s is now at %s", user, ip)
                    
                    self.users[user] = ip

                    if self.targets[target] is None:
                        log.debug("target %s not registered yet", target)
                        continue

                    response = (self.targets[target],)

                case ("server", target):

                    if target not in self.allowed_targets:
                        log.warning("server packet for target not allowed: %r", target)
                        continue

                    if self.targets[target] != ip:
                        log.info("target %s address changed", target)
                        log.debug("target %s is now at %s", target, ip)
                    
                    self.targets[target] = ip
                    response = tuple(address for address in self.users.values() if address) #could cash this response and only recompute it when the users hash changes. But for now i'll keep it as is because traffic is ment to be low

                case _:
                    log.warning("malformed packet, type %r", packet[0])
                    continue

            if response:
                plaintext = "\0".join(response).encode("utf-8")
                ciphertext = self.cryptography.encrypt(plaintext)
                try:
                    self.socket.sendto(ciphertext, source)
                except OSError as e:
                    log.warning("send failed: %s", e)

        log.debug("rx thread exiting")

    def start(self):

        if not self.socket:
            raise RuntimeError("Trying to start closed server")

        self.dead.clear()
        self.rx_thread = Thread(target=self.rx)
        self.rx_thread.start()
        log.info("started")
        certificate = OneUseData(0)
        return certificate

    def stop(self, certificate: OneUseData):

        if not self.socket:
            raise RuntimeError("Trying to stop closed server")

        certificate.get()
        self.dead.set()
        self.rx_thread.join()
        log.info("stopped")

    def close(self):

        if self.rx_thread:
            self.dead.set()
            self.rx_thread.join()

        if self.socket:
            self.socket.close()
            self.socket = None
            log.info("closed")