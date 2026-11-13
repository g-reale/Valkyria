import ipaddress
from Constans import PORT_MAX

class LimitedInteger:
    def __init__(self,number:int,minimum:int,maximum:int):
        if maximum < minimum:
            raise RuntimeError("Inverted minimum maximum range")
        if not minimum <= number <= maximum:
            raise ValueError("Number out of range")
        self.number = number

    def asNumber(self):
        return self.number

class Role:
    ALLOWED = {"client","server"}
    
    def __init__(self,role):
        if role not in Role.ALLOWED:
            raise RuntimeError("Invalid role")
        self.role = role

    def asString(self):
        return self.role 

class Protocol:

    ALLOWED = {"UDP", "TCP", "TCP/UDP"}
    
    TO_INT = {
        "TCP": 1,
        "UDP": 2,
        "TCP/UDP": 3
    }

    FROM_INT = ["TCP","UDP","TCP or UDP"]

    def __init__(self, protocol : str):

        try:
            number = int(protocol)
            if number not in range(1,len(Protocol.FROM_INT) + 1):
                raise RuntimeError("Invalid Protocol")
            self.removal_cmd = Protocol.FROM_INT[number-1]
            self.add_cmd = number
        except:
            if protocol not in Protocol.ALLOWED:
                raise RuntimeError("Invalid Protocol")
            self.removal_cmd = protocol if protocol != "TCP/UDP" else "TCP or UDP"
            self.add_cmd = Protocol.TO_INT[protocol]
    
    def asAddCommand(self):
        return self.add_cmd

    def asRemoveCommand(self):
        return self.removal_cmd
            
class PortRange:
    def __init__(self, start : int, end : int):
        if end < start or start < 0 or PORT_MAX < end:
            raise RuntimeError("Invalid port range")
        self.range = (start,end)

    def asTuple(self):
        return self.range

    def asStart(self):
        return self.range[0]

    def asEnd(self):
        return self.range[1]


class Ipv4:
    def __init__(self,ip):
        try:
            if not isinstance(ipaddress.ip_address(ip),ipaddress.IPv4Address):
                raise RuntimeError("Invalid ip")
            self.ip = ip
        except:
            raise RuntimeError("Invalid ip")

    def asString(self):
        return self.ip

class OneUseData:
        
    def __init__(self,data):
        self.data = data
        self.valid = True

    def get(self):
        if self.valid:
            self.valid = False
            return self.data
        raise RuntimeError("Onetime data used twice")