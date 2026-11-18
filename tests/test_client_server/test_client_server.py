
import unittest
import threading
import time

from client.Client import Client

# SUPOSE THE SERVER IS RUNNING WITH THE PROVIDED .JSON

# CREATE A CLIENT LIKE CLIENT CALLED GABRIEL

# DELETE GABRIEL AND CREATE A SERVER LIKE CLIENT CALLED BRUNO
# CHECK IF BRUNO RECEIVES A IP

# DELETE BRUNO AND RECREATE GABRIEL
# CHECK IF GABRIEL RECEIVES A IP

# THE IPS RECEIVED BY BOTH SHOULD BE THE SAME (THIS HOST PUBLIC IP)

class TestClientServerConnection(unittest.TestCase):

    TIMEOUT = 60
    REGISTRATION_DELAY = 30

    def setUp(self):
        self.event = threading.Event()
        self.additions = set()

    def changed(self, additions, removals):
        self.additions.update(additions)
        self.event.set()

    def wait_for_ip(self):
        self.assertTrue(self.event.wait(self.TIMEOUT),"Timed out waiting for an IP address")
        self.assertTrue(self.additions,"Callback was invoked, but no IP was received")
        return self.additions.pop()

    def start_client(self, config):
        client = Client(config, on_change=self.changed)
        certificate = client.start()
        return client, certificate

    def stop_client(self, client, certificate):
        client.stop(certificate)
        client.close()

    def test_connection(self):

        gabriel, cert = self.start_client("tests/test_client_server/!gabriel.json")

        try:
            time.sleep(self.REGISTRATION_DELAY)
        finally:
            self.stop_client(gabriel, cert)

        self.event.clear()
        self.additions.clear()
        bruno, cert = self.start_client("tests/test_client_server/!bruno.json")

        try:
            ip_a = self.wait_for_ip()
        finally:
            self.stop_client(bruno, cert)

        
        self.event.clear()
        self.additions.clear()
        gabriel, cert = self.start_client("tests/test_client_server/!gabriel.json")

        try:
            ip_b = self.wait_for_ip()
        finally:
            self.stop_client(gabriel, cert)

        self.assertEqual(ip_a, ip_b)


if __name__ == "__main__":
    unittest.main()
