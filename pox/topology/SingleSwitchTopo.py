from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    """Single switch connected to n hosts."""
    def build(self, n=2):
        switch = self.addSwitch('s1')

        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)
