from pox.misc.loadbalancing.base.iplb_base import *


class SourceHashing(iplb_base):

    def _pick_server(self, key, inport, cip):
        """Applies least connection load balancing algorithm"""
        self.log.info('Using Least Connection load balancing algorithm.')

        if not bool(self.live_servers):
            self.log.error('Error: No servers are online!')
            return

        return self.source_hashing(cip)


    # perform source hashing alg on the load balancer
    def source_hashing(self, cip):
        # sepearete the client ip octal and put into a list
        clientip = cip.toStr().split(".")
        clientipOctal = [int(i) for i in clientip]

        # multiply the client ip octal
        clientOctalVal = 1
        for clientOctal in clientipOctal:
            if clientOctal is not 0:
                clientOctalVal = clientOctalVal * clientOctal

        serverOctalMul = 1
        serverval = 1
        iplastOctal = {}
        # loop through the live servers ip and multiple the servers ip octal
        for serverip, detail in self.live_servers.items():
            # sepearete the server ip octal and put into a list
            serveripstr = serverip.toStr().split(".")
            serveripOctal = [int(i) for i in serveripstr]
            # capture the ip last octal of each live server and put into a list
            iplastOctal[serveripOctal[3]] = serverip

            # loop through all server ip and multiply their octal val
            serverOctalMul = 1
            for oct in serveripOctal:
                if oct is not 0:
                    serverOctalMul = serverOctalMul * oct

            serverval = serverval * serverOctalMul

            # multiple the client ip octal val and the servers ip octal val
        ipval = clientOctalVal * serverval

        # get the load balancing server cnt
        lbservercnt = len(self.live_servers)
        if lbservercnt < 2:
            log.debug("YOU NEED ALEAST TWO SERVERS UP FOR LOOP BALANCING, CURRENTLY USING ONE SERVER.")
            lbservercnt = 2

        # get the last 3 digits of your client and servers ip octal computed above
        ipmod = ipval % 1000

        # handle the case where ipval%1000 => 1000%1000 = 0 which would generate ip x.x.x.0 and is invalid.
        if ipmod == 0:
            ipmod = 1

        # if octal is greater than 255, loop until is less/equal to 255
        if ipmod > 255:
            while (ipmod > 255):
                ipmod = ipmod / lbservercnt
        # ipmod=215
        # sort the server ip list in ascending order
        iplastOctalsorted = {}
        iplastOctalsorted = sorted(iplastOctal.keys())

        lbserverkey = 0
        # make sure that there are live servers to handle the request.
        if len(iplastOctalsorted) > 0:
            # find a pontential range into which the client ip might fall in between to lb servers and pick the heights of the two to handle the request
            lowip = 1
            heighip = iplastOctalsorted[0]
            i = 0
            # loop until find the range on which the client ip fall between two lb servers to handle the request, always pick the heights of the two
            while (True):
                # if the computed octal falls under an ip range, that is your lb server ip to be used for source hashing.
                if lowip <= ipmod and ipmod <= heighip:
                    lbserverkey = heighip
                    return iplastOctal[lbserverkey]
                else:
                    if i + 1 >= len(iplastOctalsorted):
                        return iplastOctal[iplastOctalsorted[i]]
                    lowip = int(iplastOctal[iplastOctalsorted[i]].toStr().split(".")[3])
                    heighip = iplastOctalsorted[i + 1]
                i = i + 1

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
            if not core.hasComponent('SourceHashing'):
                # Need to initialize first...
                core.registerNew(SourceHashing, event.connection, IPAddr(ip), servers)
                log.info("IP Load Balancer Ready.")
            log.info("Load Balancing on %s", event.connection)

            # Gross hack
            core.SourceHashing.con = event.connection
            event.connection.addListeners(core.SourceHashing)

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
