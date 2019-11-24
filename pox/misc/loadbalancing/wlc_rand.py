from pox.misc.loadbalancing.lb_weighted_least_connection import WeightedLeastConnection
from pox.misc.loadbalancing.base.lblc_base import *


class RandWLC(WeightedLeastConnection):
    """Variant of RandWLC that assigns random weights to servers"""
    def __init__(self, server, first_packet, client_port):
        super(RandWLC, self).__init__(server, first_packet, client_port)
        self.server_weight = {k: random.randint(1, 5) for k in self.servers}
        self.log.debug('Randomized Server Weights: {}'.format(self.server_weight))

# Remember which DPID we're operating on (first one to connect)
_dpid = None


def launch(ip, servers, dpid=None):
    global _dpid
    if dpid is not None:
        _dpid = str_to_dpid(dpid)

    servers = servers.replace(",", " ").split()
    servers = [IPAddr(x) for x in servers]
    ip = IPAddr(ip)

    # We only want to enable ARP Responder *only* on the load balancer switch,
    # so we do some disgusting hackery and then boot it up.
    from proto.arp_responder import ARPResponder
    old_pi = ARPResponder._handle_PacketIn

    def new_pi(self, event):
        if event.dpid == _dpid:
            # Yes, the packet-in is on the right switch
            return old_pi(self, event)

    ARPResponder._handle_PacketIn = new_pi

    # Hackery done.  Now start it.
    from proto.arp_responder import launch as arp_launch
    arp_launch(eat_packets=False, **{str(ip): True})
    import logging
    logging.getLogger("proto.arp_responder").setLevel(logging.WARN)

    def _handle_ConnectionUp(event):
        global _dpid
        if _dpid is None:
            _dpid = event.dpid

        if _dpid != event.dpid:
            log.warn("Ignoring switch %s", event.connection)
        else:
            if not core.hasComponent('RandWLC'):
                # Need to initialize first...
                core.registerNew(RandWLC, event.connection, IPAddr(ip), servers)
                log.info("IP Load Balancer Ready.")
            log.info("Load Balancing on %s", event.connection)

            # Gross hack
            core.RandWLC.con = event.connection
            event.connection.addListeners(core.RandWLC)

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
