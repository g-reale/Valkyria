import json
import socket
from Constans import BUFFER_SIZE, PORT_MAX, TIMEOUT, HOST
from base64 import b64decode
from threading import Thread, Event
from Types import OneUseData, LimitedInteger
from Cryptography import Cryptography

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

    def rx(self): # process one client at a time, single threaded server
        while not self.dead.is_set():

            try:
                raw, source = self.socket.recvfrom(BUFFER_SIZE)
            except (socket.timeout, ConnectionResetError):
                continue

            try:
                decyphered = self.cryptography.decrypt(raw)
                packet = tuple(word for word in decyphered.split("\0"))
                response = None
            except (RuntimeError):
                continue

            match packet:

                case ("client", user, target):
                    
                    if user not in self.allowed_users:
                        continue
                    if target not in self.allowed_targets:
                        continue

                    self.users[user] = source

                    if self.targets[target] is None:
                        continue

                    response = (self.targets[target][0],)

                case ("server",target):

                    if target not in self.allowed_targets:
                        continue
                    self.targets[target] = source
                    response = tuple(address[0] for address in self.users.values() if address) #could cash this response and only recompute it when the users hash changes. But for now i'll keep it as is because traffic is ment to be low

                case _:
                    continue

            if response:
                plaintext = "\0".join(response).encode("utf-8")
                ciphertext = self.cryptography.encrypt(plaintext)
                try:
                    self.socket.sendto(ciphertext, source)
                except OSError:
                    pass

    def start(self):

        if not self.socket:
            raise RuntimeError("Trying to start closed server")

        self.dead.clear()
        self.rx_thread = Thread(target=self.rx)
        self.rx_thread.start()
        certificate = OneUseData(0)
        return certificate

    def stop(self, certificate: OneUseData):

        if not self.socket:
            raise RuntimeError("Trying to stop closed server")

        certificate.get()
        self.dead.set()
        self.rx_thread.join()

    def close(self):

        if self.rx_thread:
            self.dead.set()
            self.rx_thread.join()

        if self.socket:
            self.socket.close()
            self.socket = None
        