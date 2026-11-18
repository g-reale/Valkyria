import time
import socket
from contextlib import contextmanager

import requests

from Client import Client
from AccessPoint import AccessPoint
from Types import PortRange, Ipv4, Protocol


class PortMaker:

    PREFIX = "valkyria_"
    RETRIES = 3
    MINECRAFT_PORT = PortRange(25585, 25585)

    def __init__(self, config_path):

        self.ap = AccessPoint(config_path)
        self.private_ip = Ipv4(self._getPrivateIp())
        PortMaker._retry(self._clearRules)
        self.client = Client(config_path, self.onIpChanges)
        self.client.start()

    def _retry(function, /, *args, **kwargs):

        for attempt in range(PortMaker.RETRIES):
            try:
                return function(*args, **kwargs)
            except:
                if attempt == PortMaker.RETRIES - 1:
                    raise RuntimeError("Could not perform operation")
                time.sleep(attempt + 1)

    @staticmethod
    def _name(ip):
        return PortMaker.PREFIX + ip.replace(".", "_")

    def _getPrivateIp(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((self.ap.gateway, 80))
            return s.getsockname()[0]
        finally:
            s.close()

    @contextmanager
    def _session(self):
        self.ap.login()
        try:
            yield self.ap.getRules()
        finally:
            self.ap.logout()

    def _clearRules(self):

        with self._session() as key:
            for name in [n for n in self.ap.rules if n.startswith(PortMaker.PREFIX)]:
                key = self.ap.removeRule(name, key, False)

    def _add(self, ip):

        name = PortMaker._name(ip)
        with self._session() as key:
            if name in self.ap.rules:
                return
            self.ap.addRule(
                name=name,
                remote_ip=Ipv4(ip),
                server_ip=self.private_ip,
                protocol=Protocol("TCP"),
                external_port_range=PortMaker.MINECRAFT_PORT,
                internal_port_range=PortMaker.MINECRAFT_PORT,
                config_session_key=key,
                reboot=False
            )
            if name not in self.ap.rules:
                raise RuntimeError(f"Rule {name} was not added")

    def _remove(self, ip):

        name = PortMaker._name(ip)
        with self._session() as key:
            if name not in self.ap.rules:
                return
            self.ap.removeRule(name, key, False)
            if name in self.ap.rules:
                raise RuntimeError(f"Rule {name} was not removed")

    def onIpChanges(self, additions, removals):

        for ip in additions:
            PortMaker._retry(self._add, ip)

        for ip in removals:
            PortMaker._retry(self._remove, ip)

    def close(self):

        self.client.close()
        PortMaker._retry(self._clearRules)