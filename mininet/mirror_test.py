from argparse import ArgumentParser
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController
from multiprocessing import Process
import time


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
    Builds default mininet topology with n servers and 2n nodes.
    """
    parser = ArgumentParser(description='Test Topology that Runs two Traffic Generators in Parallel to hit the '
                                        'POX Controller at 10.0.1.1')
    parser.add_argument("-p", type=int, help="number of packets for each node to send (total sent "
                                             "will be this value times the number of clients (p*s))", required=True)
    parser.add_argument("-s", type=int, help="Number of servers. Total number of hosts will be double this.",
                        required=True)
    args = parser.parse_args()

    num_packets = args.p
    size = 2*args.s
    servs = args.s
    topo = SingleSwitchTopo(n=size)

    controller = RemoteController(name='custom_pox', ip='0.0.0.0', port=6633)
    mininet = Mininet(topo=topo, controller=controller)
    mininet.start()

    print("Spinning up Default Load Balancing Test Topology with {} total nodes and {} servers.".format(size, servs))

    for i in range(servs):
        h = mininet.hosts[i]
        h.cmd("python -m SimpleHTTPServer 80 &")
        print("{} now running SimpleHTTPServer".format(h))

    try:
        print("Warning! Make sure POX and three tshark instances (one for each server) are running!")
        raw_input("Press any key to continue ")

        print("Firing {} requests each from remaining hosts...".format(num_packets))
        clients = [mininet.hosts[servs+i] for i in range(servs)]

        def run(h):
            h.cmd("sudo python pox/misc/loadbalancing/utils/get_stats.py -s 10.0.1.1 -n {} -d 0".format(num_packets))

        processes = [Process(target=run, args=(client,)) for client in clients]

        print("Running get_stats in parallel across nodes: {}".format(clients))

        for process in processes:
            process.start()

        for process in processes:
            process.join()

        time.sleep(2)
    finally:
        mininet.stop()


if __name__ == '__main__':
    """To spin up this mininet topology, simply run this as a normal python script with sudo permissions."""
    start()
