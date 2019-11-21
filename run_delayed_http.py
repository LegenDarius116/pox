import SocketServer
from pox.misc.loadbalancing.utils.DelayedHTTPServer import DelayedHTTPServer


def main():
    httpd = SocketServer.TCPServer(("", 80), DelayedHTTPServer)
    print("Running SimpleHTTPServer with Artificial Delay injected")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
