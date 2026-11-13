import json
import subprocess
import re
import hashlib
import base64
import requests
from Types import PortRange, Protocol, OneUseData, Ipv4

class AccessPoint:


    RULE_PARSER = re.compile(
        r"(?P<name>\w+)/"
        r"(?P<external_port_start>\d+)/"
        r"(?P<external_port_end>\d+)/"
        r"(?P<internal_ip>\d{1,3}(?:\.\d{1,3}){3})/"
        r"(?P<internal_port_start>\d+)/"
        r"(?P<internal_port_end>\d+)/"
        r"(?P<protocol>\d+)/"
        r"(?P<external_ip>\d{1,3}(?:\.\d{1,3}){3})"
    )

    def __init__(self, config_path):
        text = subprocess.getoutput("ipconfig")
        gateways = re.findall(r".*Gateway.*?: ([\d.]+)", text)
        gateways = [gw for gw in gateways if gw != "0.0.0.0"]

        if not gateways:
            raise RuntimeError("Could not find the gateway")

        self.gateway = gateways[0]

        try:
            with open(config_path, "r", encoding="utf-8") as file:
                configs = json.load(file)
            self.user = configs["ap_user"]
            self.password = configs["ap_password"]

        except (OSError, json.JSONDecodeError, KeyError) as e:
            raise RuntimeError(
                "Could not load configuration or required keys"
            ) from e

        self.session = requests.Session()
        self.rules = {}

    def getVar(variable, text):
        match = re.search(
            rf'\bvar\s+{re.escape(variable)}\s*=\s*([^;\s]+)',
            text
        )
        if match:
            return match.group(1).strip('"\'')
        else:
            raise RuntimeError(f"Variable '{variable}' not found")

    def _getSessionKey(self,sid):
        hash = hashlib.md5(
            f"{sid}:{self.password}".encode("utf-8")
        ).hexdigest()
        session_key = base64.b64encode(
            f"{self.user}:{hash}".encode("utf-8")
        ).decode("ascii")
        return session_key

    def _getSid(self):
        response = self.session.get(
            f"http://{self.gateway}/login_frame.html",
            timeout=5
        )
        return AccessPoint.getVar("sid",response.text)

    def verifyResponse(function):
        def wrapper(*args, **kwargs):
            output = function(*args, **kwargs)

            if isinstance(output, tuple):
                response, result = output
            else:
                response = output
                result = output
            
            if not response:
                RuntimeError("Verifing function wo a response variable")
            
            if response.status_code != 200:
                RuntimeError("Failed response")

            return result
        return wrapper

    def _refreshRules(self,response):
        
        self.rules.clear()
        rules = AccessPoint.getVar("portForwarding",response.text)
        index = 0

        for match in AccessPoint.RULE_PARSER.finditer(rules):
            rule = match.groupdict()
            self.rules[rule["name"]] = rule
            self.rules[rule["name"]]["index"] = index
            index += 1

        config_session_key = AccessPoint.getVar("sessionKey",response.text)
        return OneUseData(config_session_key)

    @verifyResponse
    def login(self):
        sid = self._getSid()
        self.session_key = self._getSessionKey(sid)
        response = self.session.post(
            f"http://{self.gateway}/login-login.cgi",
            data={
                "sessionKey": self.session_key,
                "user": self.user,
                "pass": ""
            },
            timeout=5
        )

        return response

    @verifyResponse
    def logout(self):
        response = self.session.get(
            f"http://{self.gateway}/logout.cmd",
            timeout=5
        )
        return response

    @verifyResponse
    def getRules(self):
        response = self.session.get(
            f"http://{self.gateway}/settings-local-network.html",
            timeout=5
        )
        return response,self._refreshRules(response)

    @verifyResponse
    def addRule(
        self, 
        name : str, 
        remote_ip : Ipv4, 
        server_ip : Ipv4, 
        protocol : Protocol, 
        external_port_range : PortRange, 
        internal_port_range : PortRange, 
        config_session_key : OneUseData, 
        reboot : bool
    ):
    
        parameters = {
            "action":       "add",
            "srvName":      f"{name}",
            "dstWanIf":     "",
            "remoteAddr":   f"{remote_ip.asString()}",
            "srvAddr":      f"{server_ip.asString()}",
            "proto":        f"{protocol.asAddCommand()},",
            "eStart":       f"{external_port_range.asStart()},",
            "eEnd":         f"{external_port_range.asEnd()},",
            "iStart":       f"{internal_port_range.asStart()},",
            "iEnd":         f"{internal_port_range.asEnd()},",
            "sessionKey":   f"{config_session_key.get()}",
            "reboot":       f"{int(reboot)}"
        }
        
        response = self.session.get(
            f"http://{self.gateway}/scvrt_srv_gvt.cmd",
            params=parameters,
            timeout=5
        )

        return response,self._refreshRules(response)

    @verifyResponse
    def removeRule(
        self, 
        name : str, 
        config_session_key : OneUseData, 
        reboot : bool
    ):
        
        if name not in self.rules:
            raise RuntimeError("Tring to delete non existent rule")

        rule = self.rules[name]
        
        rm_lst = "|".join([
            rule["internal_ip"],
            rule["external_port_start"],
            rule["external_port_end"],
            Protocol(rule["protocol"]).asRemoveCommand(),
            rule["internal_port_start"],
            rule["internal_port_end"]
        ])

        parameters = {
            "action":       "remove",
            "rmLst":        rm_lst,
            "sessionKey":   config_session_key.get(),
            "reboot" :      f"{int(reboot)}"
        }

        response = self.session.get(
            f"http://{self.gateway}/scvrt_srv_gvt.cmd",
            params=parameters,
            timeout=5
        )

        return response,self._refreshRules(response)

    @verifyResponse
    def updateRule(
        self,
        name: str,
        config_session_key: OneUseData,
        reboot: bool,
        remote_ip: Ipv4 | None = None,
        server_ip: Ipv4 | None = None,
        protocol: Protocol | None = None,
        external_port_range: PortRange | None = None,
        internal_port_range: PortRange | None = None
    ):
        if name not in self.rules:
            raise RuntimeError("Trying to update non existent rule")

        rule = self.rules[name]

        def choose(new, old):
            return old if new is None else new

        remote_ip = choose(remote_ip, Ipv4(rule["external_ip"]))
        server_ip = choose(server_ip, Ipv4(rule["internal_ip"]))
        protocol = choose(protocol, Protocol(rule["protocol"]))
        external_port_range = choose(external_port_range,PortRange(
                int(rule["external_port_start"]),
                int(rule["external_port_end"])
            )
        )
        internal_port_range = choose(
            internal_port_range,
            PortRange(
                int(rule["internal_port_start"]),
                int(rule["internal_port_end"])
            )
        )

        parameters = {
            "action":       "update",
            "index":        str(rule["index"]),
            "srvName":      name,
            "dstWanIf":     "",
            "remoteAddr":   remote_ip.asString(),
            "srvAddr":      server_ip.asString(),
            "proto":        f"{protocol.asAddCommand()},",
            "eStart":       f"{external_port_range.asStart()},",
            "eEnd":         f"{external_port_range.asEnd()},",
            "iStart":       f"{internal_port_range.asStart()},",
            "iEnd":         f"{internal_port_range.asEnd()},",
            "sessionKey":   config_session_key.get(),
            "reboot":       str(int(reboot))
        }

        response = self.session.get(
            f"http://{self.gateway}/scvrt_srv_gvt.cmd",
            params=parameters,
            timeout=5
        )

        return response, self._refreshRules(response)
