from pox.misc.loadbalancing.base.lblc_base import *


class WeightedLeastConnection(lblc_base):

    def __init__(self, server, first_packet, client_port):
        """Extend the __init__ function with extra fields"""
        super(WeightedLeastConnection, self).__init__(server, first_packet, client_port)

        # create dictionary to show each server's weight
        # NOTE: Since each node is virtual, they will all have the same weight 1.
        #       Also, since weight represents a node's hardware capability, it is immutable.
        self.server_weight = {k: 1 for k in self.servers}
        self.log.debug('Server Weights: {}'.format(self.server_weight))

    def _pick_server(self, key, inport):
        """Applies weighted least connection load balancing algorithm"""
        self.log.info('Using Weighted Least Connection load balancing algorithm.')
        self.log.debug("Current Load Counter: {}".format(self.server_load))  # debug

        if not bool(self.live_servers):
            self.log.error('Error: No servers are online!')
            return

        """
        Find the server with the least load. If several servers all have the minimum load,
        pick the one with the highest weight value (most capable of handling the new connection).
        """
        min_servers = self.get_minimally_loaded_servers()

        # slice the self.server_weight dictionary to only have minimally loaded servers
        weight_sliced = {k: v for k, v in self.server_weight.items() if k in min_servers}

        # pick the minimally loaded server with the highest weight
        server = max(weight_sliced, key=weight_sliced.get)

        # increment that server's load counter
        # NOTE: When evaluating these algorithms, create a more realistic env
        self._mutate_server_load(server, 'inc')

        return server

    def get_minimally_loaded_servers(self):
        """Returns a list of servers that all have the minimum load"""
        min_load = min(self.server_load.values())
        return [serv for serv in self.server_load.keys() if self.server_load[serv] == min_load]


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
            if not core.hasComponent('WeightedLeastConnection'):
                # Need to initialize first...
                core.registerNew(WeightedLeastConnection, event.connection, IPAddr(ip), servers)
                log.info("IP Load Balancer Ready.")
            log.info("Load Balancing on %s", event.connection)

            # Gross hack
            core.WeightedLeastConnection.con = event.connection
            event.connection.addListeners(core.WeightedLeastConnection)

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
