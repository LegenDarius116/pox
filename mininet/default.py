from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController
from argparse import ArgumentParser


class SingleSwitchTopo(Topo):
    """Single switch connected to n hosts."""
    def build(self, n=2):
        switch = self.addSwitch('s1')

        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)


def start():
    """
    Builds default mininet topology with N nodes. N-1 of those nodes are servers, while 1 is a client, which
    we will use as a traffic generator to test our load balancing algorithms.
    """
    parser = ArgumentParser(description='Default Load Balancing Test Mininet Topology')
    parser.add_argument("-n", type=int, help="number of hosts", required=True)
    parser.add_argument("-s", type=int, help="number of servers")
    args = parser.parse_args()

    size = args.n
    if not args.s:
        servs = size - 1
        print("-s not provided. Defaulting to n-1 ({})".format(servs))
    else:
        servs = args.s

    if size <= 0:
        raise ValueError("Cannot have negative number of hosts.")

    if servs <= 0:
        raise ValueError("Cannot have negative number of servers")

    if size < servs:
        raise ValueError("The number of servers is larger than the total number of hosts! ({} > {})".format(
            servs, size
        ))

    topo = SingleSwitchTopo(n=size)

    controller = RemoteController(name='custom_pox', ip='0.0.0.0', port=6633)
    mininet = Mininet(topo=topo, controller=controller)
    mininet.start()

    command = "python -m SimpleHTTPServer 80 &"

    print("Spinning up Default Load Balancing Test Topology with {} total nodes and {} servers.".format(size, servs))

    for i in range(servs):
        h = mininet.hosts[i]
        h.cmd(command)
        print("{} now running SimpleHTTPServer".format(h))

    try:
        CLI(mininet)
    finally:
        mininet.stop()


if __name__ == '__main__':
    """To spin up this mininet topology, simply run this as a normal python script with sudo permissions."""
    start()
