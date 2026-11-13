import json
import socket
from base64 import b64decode
from Cryptography import Cryptography
from Constans import BUFFER_SIZE, PORT_MAX, HOST, TIMEOUT, PERIOD_MIN, PERIOD_MAX
from threading import Thread, Event
from Types import OneUseData, Ipv4, Role, LimitedInteger

# use simetrical encryption everywhere (for all client types and the valkyria server)
                
# client package types (send every n seconds):
# client type client: encript(role |\0| valkyria_user |\0| valkyria_target |\0)
# server type client: encript(role |\0| valkyria_user)

# server packge types (in response to client packages):
# server to client type: encript(target_ip)
# server to server type: encript(sorce_ip_0|sorce_ip_1|...|source_ip_n) (non scalable, i'm aiminimumg for a tiny number of clients)

class Client:

    def __init__(self,config_path):
        
        # let exceptions break the client on config
        with open(config_path, "r", encoding="utf-8") as file:
            configs = json.load(file)
        self.role               = Role(configs["valkyria_role"])
        self.valkyria_ip        = Ipv4(configs["valkyria_ip"])
        self.valkyria_key       = b64decode(configs["valkyria_key"])
        self.valkyria_user      = configs["valkyria_user"]
        self.valkyria_port      = LimitedInteger(configs["valkyria_port"],0,PORT_MAX)
        self.valkyria_period    = LimitedInteger(configs["valkyria_period"],PERIOD_MIN,PERIOD_MAX)

        self.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.socket.bind((HOST,self.valkyria_port.asNumber()))
        self.socket.settimeout(TIMEOUT)
        self.valkyria_address = (self.valkyria_ip.asString(),self.valkyria_port.asNumber())
        self.cryptography = Cryptography(self.valkyria_key)
        self.tx_thread = None
        self.rx_thread = None
        self.dead = Event()
        self.ips = []
        
        if self.role.asString() == "client":
            self.valkyria_target = configs["valkyria_target"]
            self.packet = f"client\0{self.valkyria_user}\0{self.valkyria_target}".encode("utf-8")
        else: 
            self.packet = f"server\0{self.valkyria_user}".encode("utf-8")
            

    def tx(self):

        while not self.dead.is_set():
            cyphered = self.cryptography.encrypt(self.packet)
            try:
                self.socket.sendto(cyphered, self.valkyria_address)
            except OSError:
                pass
            self.dead.wait(self.valkyria_period.asNumber())


    def rx(self):
        
        while not self.dead.is_set():
            
            try:
                raw, source = self.socket.recvfrom(BUFFER_SIZE)
            except (socket.timeout, ConnectionResetError):
                continue
                
            if source != self.valkyria_address:
                continue

            try:
                decyphered = self.cryptography.decrypt(raw)
                ips = [Ipv4(ip).asString() for ip in decyphered.split("\0") if ip]
                self.ips = ips
            except (RuntimeError):
                continue
            
    def start(self):

        if not self.socket:
            raise RuntimeError("Trying to start closed client")

        self.dead.clear()
        self.tx_thread = Thread(target=self.tx)
        self.rx_thread = Thread(target=self.rx)
        self.tx_thread.start()
        self.rx_thread.start()
        certificate = OneUseData(0)
        return certificate

    def stop(self, certificate : OneUseData):

        if not self.socket:
            raise RuntimeError("Trying to stop closed client")

        certificate.get()
        self.dead.set()
        self.tx_thread.join()
        self.rx_thread.join()

    def close(self):

        if self.rx_thread:
            self.dead.set()
            self.tx_thread.join()
            self.rx_thread.join()

        if self.socket:
            self.socket.close()
            self.socket = None
        
