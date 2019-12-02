from pox.misc.loadbalancing.base.lblc_base import *
import random

NUM_OF_IPS = 3

class DestinationHashing(lblc_base):

    def _pick_server(self, key, inport):
        """Applies Destination Hashing  load balancing algorithm"""
        self.log.info('Using Destination Hashing  load balancing algorithm.')
        self.log.debug("Current Load Counter: {}".format(self.server_load))  # debug

        if not bool(self.live_servers):
            self.log.error('Error: No servers are online!')
            return

        server = self._dest_hash_pick(self.server_load)

        # increment that server's load counter
        # NOTE: When evaluating these algorithms, create a more realistic env
        self._mutate_server_load(server, 'inc')

        return server

    def _dest_hash_pick(self, servers):
        servers_list = list(servers)
        num_of_servers = len(servers_list)
        max_load = servers[max(servers, key=servers.get)]
        key = random.randint(0, NUM_OF_IPS-1)
        hash_key = self._hash_function(key, max_load, num_of_servers)
        return servers_list[hash_key]

    def _hash_function(self, key, max_load, num_of_servers):
        hash_key = (key + max_load)%num_of_servers
        return hash_key

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
            if not core.hasComponent('DestinationHashing'):
                # Need to initialize first...
                core.registerNew(DestinationHashing, event.connection, IPAddr(ip), servers)
                log.info("IP Load Balancer Ready.")
            log.info("Load Balancing on %s", event.connection)

            # Gross hack
            core.DestinationHashing.con = event.connection
            event.connection.addListeners(core.DestinationHashing)

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
