import SimpleHTTPServer
import time


class DelayedHTTPServer(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """Simple extension of SimpleHTTPServer that adds artificial delay"""

    def do_GET(self):
        """Extend do_GET to have an artificial delay of 13 ms"""
        time.sleep(.013)
        super(DelayedHTTPServer, self).do_GET()
