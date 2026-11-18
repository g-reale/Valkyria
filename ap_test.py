from pprint import pprint
from client.AccessPoint import AccessPoint, Protocol, Ipv4, PortRange

ap = AccessPoint('config.json')
ap.login()
config_session_key = ap.getRules()

config_session_key = ap.addRule(
    "gabiru",
    Ipv4("122.122.122.122"),
    Ipv4("133.133.133.133"),
    Protocol("TCP/UDP"),
    PortRange(80,80),
    PortRange(90,90),
    config_session_key,
    False
)

pprint(ap.rules)

config_session_key = ap.updateRule(
    "gabiru",
    config_session_key=config_session_key,
    reboot=False,
    remote_ip=Ipv4("133.133.133.133")
)

pprint(ap.rules)

config_session_key = ap.removeRule("gabiru",config_session_key,False)

pprint(ap.rules)

ap.logout()