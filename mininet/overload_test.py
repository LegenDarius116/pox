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
    Builds default mininet topology with 4 clients and 3 servers. Tests the scenario where we are overloading the load
    balancing server
    """
    size = 7
    servs = 3
    topo = SingleSwitchTopo(n=size)

    parser = ArgumentParser(description='Builds default mininet topology with 4 clients and 3 servers. '
                                        'Tests the scenario where we are overloading the load '
                                        'balancing server at 10.0.1.1.')
    parser.add_argument("-p", type=int, help="number of packets for each node to send (total sent "
                                             "will be quadruple this)", required=True)
    args = parser.parse_args()
    num_packets = args.p

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

        print("Firing {} requests each from h4-h7...".format(num_packets))
        h4 = mininet.hosts[3]
        h5 = mininet.hosts[4]
        h6 = mininet.hosts[5]
        h7 = mininet.hosts[6]

        def run(h):
            h.cmd("sudo python pox/misc/loadbalancing/utils/purefire.py -s 10.0.1.1 -n {}".format(num_packets))

        tg1 = Process(target=run, args=(h4,))
        tg2 = Process(target=run, args=(h5,))
        tg3 = Process(target=run, args=(h6,))
        tg4 = Process(target=run, args=(h7,))

        print("Running get_stats in parallel...")

        tg1.start()
        tg2.start()
        tg3.start()
        tg4.start()

        tg1.join()
        tg2.join()
        tg3.join()
        tg4.join()

        time.sleep(2)
    finally:
        mininet.stop()


if __name__ == '__main__':
    """To spin up this mininet topology, simply run this as a normal python script with sudo permissions."""
    start()
