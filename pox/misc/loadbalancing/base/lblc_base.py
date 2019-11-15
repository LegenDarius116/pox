from pox.misc.loadbalancing.base.iplb_base import *
from threading import Lock
import re
import os

class lblc_base(iplb_base):
    """
    An abstract class to make the code for Least Connection and Weighted Least Connection more DRY
    """

    def __init__(self, server, first_packet, client_port):
        """Extend the __init__ function with extra fields"""
        super(lblc_base, self).__init__(server, first_packet, client_port)

        # create dictionary to track how many active connections each server has
        self.server_load = {k: 0 for k in self.servers}

        self.log.debug('server_load initial state: {}'.format(self.server_load))

        # create mutexes to be used by each server
        self.locks = {k: Lock() for k in self.servers}

    def _mutate_server_load(self, server, op):
        """Increments/Decrements one of the live server's load by 1. A mutex is used to prevent race conditions.

        :param server:  key that represents the server node
        :param op:      opcode string that either increments or decrements
        """
        if op not in ['inc', 'dec']:
            raise ValueError('Error: Invalid op argument')

        self.locks[server].acquire()
        try:
            if op == 'inc':
                self.server_load[server] = self.server_load[server] + 1
            elif op == 'dec':
                self.server_load[server] = self.server_load[server] - 1

                if self.server_load[server] < 0:
                    self.log.error("Load of Server {} has gone negative!".format(server))
            else:
                raise ValueError('Error: Invalid op argument')
        finally:
            self.locks[server].release()

    def _handle_PacketIn(self, event):
        """Overwriting the base function. Injecting a line that decreases load counter when server writes back."""

        inport = event.port
        packet = event.parsed

        def drop():
            if event.ofp.buffer_id is not None:
                # Kill the buffer
                msg = of.ofp_packet_out(data=event.ofp)
                self.con.send(msg)
            return None

        tcpp = packet.find('tcp')
        if not tcpp:
            arpp = packet.find('arp')
            if arpp:
                # Handle replies to our server-liveness probes
                if arpp.opcode == arpp.REPLY:
                    if arpp.protosrc in self.outstanding_probes:
                        # A server is (still?) up; cool.
                        del self.outstanding_probes[arpp.protosrc]
                        if (self.live_servers.get(arpp.protosrc, (None, None))
                                == (arpp.hwsrc, inport)):
                            # Ah, nothing new here.
                            pass
                        else:
                            # Ooh, new server.
                            self.live_servers[arpp.protosrc] = arpp.hwsrc, inport
                            self.log.info("Server %s up", arpp.protosrc)
                return

                # Not TCP and not ARP.  Don't know what to do with this.  Drop it.
            return drop()

            # It's TCP.

        ipp = packet.find('ipv4')

        if ipp.srcip in self.servers:
            # It's FROM one of our balanced servers.
            # Rewrite it BACK to the client

            key = ipp.srcip, ipp.dstip, tcpp.srcport, tcpp.dstport
            entry = self.memory.get(key)

            if entry is None:
                # We either didn't install it, or we forgot about it.
                self.log.debug("No client for %s", key)
                return drop()

            # Refresh time timeout and reinstall.
            entry.refresh()

            # Install reverse table entry
            mac, port = self.live_servers[entry.server]

            # Server wrote back, decrease it's active load counter
            if not os.environ.get('AWS', False):
                # If this is on Mininet VM, server only writes back one packet. Decrease the load on that one.
                self._mutate_server_load(entry.server, 'dec')
                self.log.debug("Packet detected. Hoping it's only one. Decreasing load of {}.".format(
                    entry.server
                ))
                self.log.debug("Current Load Counter: {}".format(self.server_load))
            else:
                # On AWS nodes, only decrement if a certain header string is matched.
                #   NOTE:   If this is true, the server sent back a response. And we are counting it once, even
                #           if multiple packets are sent back. We know that multiple packets are sent per request on
                #           Mininet topologies running on AWS ubuntu nodes. This is to make the algorithm more
                #           machine-independent.
                #   NOTE:   This method may be susceptible to packet loss
                if re.findall(r"HTTP/\d{1}\.\d{1} \d{3}", packet.raw):
                    self._mutate_server_load(entry.server, 'dec')
                    self.log.debug("Server HTTP response detected on AWS Machine. Decreasing load of {}.".format(
                        entry.server
                    ))
                    self.log.debug("Current Load Counter: {}".format(self.server_load))

            actions = []
            actions.append(of.ofp_action_dl_addr.set_src(self.mac))
            actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
            actions.append(of.ofp_action_output(port=entry.client_port))
            match = of.ofp_match.from_packet(packet, inport)

            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                  idle_timeout=FLOW_IDLE_TIMEOUT,
                                  hard_timeout=of.OFP_FLOW_PERMANENT,
                                  data=event.ofp,
                                  actions=actions,
                                  match=match)
            self.con.send(msg)

        elif ipp.dstip == self.service_ip:
            # Ah, it's for our service IP and needs to be load balanced

            # Do we already know this flow?
            key = ipp.srcip, ipp.dstip, tcpp.srcport, tcpp.dstport
            entry = self.memory.get(key)
            if entry is None or entry.server not in self.live_servers:
                # Don't know it (hopefully it's new!)
                if len(self.live_servers) == 0:
                    self.log.warn("No servers!")
                    return drop()

                # Pick a server for this flow
                server = self._pick_server(key, inport)
                self.log.debug("Directing traffic to %s", server)
                self.log.debug("Current Load Counter: {}".format(self.server_load))     #debug
                entry = MemoryEntry(server, packet, inport)
                self.memory[entry.key1] = entry
                self.memory[entry.key2] = entry

            # Update timestamp
            entry.refresh()

            # Set up table entry towards selected server
            mac, port = self.live_servers[entry.server]

            actions = []
            actions.append(of.ofp_action_dl_addr.set_dst(mac))
            actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
            actions.append(of.ofp_action_output(port=port))
            match = of.ofp_match.from_packet(packet, inport)

            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                  idle_timeout=FLOW_IDLE_TIMEOUT,
                                  hard_timeout=of.OFP_FLOW_PERMANENT,
                                  data=event.ofp,
                                  actions=actions,
                                  match=match)
            self.con.send(msg)

