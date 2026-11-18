import sys
import logging
import signal 
from server.Server import Server

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr,level=logging.INFO,format="%(levelname)s %(name)s: %(message)s")
    server = Server("server/!server.json")
    certificate = server.start()
    signal.sigwait({signal.SIGTERM, signal.SIGINT})
    server.close()

