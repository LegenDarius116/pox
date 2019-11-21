from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController


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
    Builds default mininet topology with 5 nodes and 3 servers.
    """
    size = 5
    servs = 3
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
        print("Warning! Make sure POX and three tshark instances (one for each server) are running!")
        raw_input("Press any key to continue ")

        print("Firing 100 requests each from h4 and h5...")
        h4 = mininet.hosts[3]
        h5 = mininet.hosts[4]

        h4.cmd("cd pox/misc/loadbalancing/utils")
        h5.cmd("cd pox/misc/loadbalancing/utils")

        h4.cmd("sudo python get_stats.py -s 10.0.1.1 -n 100 -d 0")
        h5.cmd("sudo python get_stats.py -s 10.0.1.1 -n 100 -d 0")

        CLI(mininet)
    finally:
        mininet.stop()


if __name__ == '__main__':
    """To spin up this mininet topology, simply run this as a normal python script with sudo permissions."""
    start()
