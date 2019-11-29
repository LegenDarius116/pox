# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from pox.lib.addresses import IPAddr
from pox.openflow.libopenflow_01 import ofp_phy_port
from math import floor

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.revent import *
from pox.lib.packet.lldp import management_address
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
import struct
from pox.lib.addresses import *
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer

import time
from pox.lib.packet.tcp import tcp

log = core.getLogger()


# FLOW_IDLE_TIMEOUT = 10

# store client/server info
class Machine():
    def __init__(self, ip, mac, port, tm):
        self.ip = ip
        self.mac = mac
        self.port = port
        self.updatedTime = tm


# store client/server flows
# map client to server and server to client
# sysflow is the flow match encapsulating the flowmatch. the flow match is the source.
class SysFlow():
    def __init__(self, source, destination, dir, idleTime, hardTime):
        self.source = source
        self.destination = destination
        self.dir = dir
        self.idleTime = idleTime
        self.hardTime = hardTime


def dpid_to_mac(dpid):
    return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class SH_LoadBalancing():
    ARP_TIMER = 1
    LLDP_TIMER = 1
    TIMER_SET = 0

    def __init__(self, connection, service_ip, servers=[], alg="sourcehashing", arp_timer=0, lldp_timer=1):

        if arp_timer == SH_LoadBalancing.ARP_TIMER and lldp_timer == SH_LoadBalancing.LLDP_TIMER:
            log.debug(
                "You have set arp_timer and lldp_timer parameters to 1. Both parameter cannot be 1, change one parameter to 0 on the launch function.")
            return

        self.con = connection  # connectino var
        self.service_ip = IPAddr(service_ip)  # service ip is the ovs switch ip
        self.service_mac = self.con.eth_addr  # service ip is the ovs switch mac

        # store initial live servers.
        self.servers = [IPAddr(a) for a in servers]

        self.alg = alg

        # live servers ip table for server mac and port number
        self.live_servers = {}  # IP -> MAC,port
        self.controller_prt = None

        # switch data path
        self.dpid = connection.dpid

        # store client/server flow generated. map client ip to server ip and serverip to clientip
        self.sys_flow = {}
        self.sys_flow[connection.dpid] = {}

        self.predefined_client_key = {}
        self.predefined_client_key_low_network = 2
        self.predefined_client_key_heigh_network = 5

        # set timers variables
        self.arp_timeout = 4  # perform arp request every y seconds to all lb servers.
        self.server_timeout = 15  # check if server is up every x seconds by responding to arp requests. each lb server needs to response atleast once in every x sec.

        self.arp_timer = arp_timer
        self.lldp_timer = lldp_timer

        self.server_client_flow_timeout = 60 * 5  # check if the client have performed request in the last z seconds
        self.flow_idle_time = 15  # flows are removed from  ovs switch if client have not perform requests in the last y sec.
        self.flow_hard_time = 30  # flows time to live in ovs switch if no client request have been placed in the last x sec. remove flows from ovs switch after x sec have elapse no matter if the client have perform request or not in the last x sec, ie, hard time out

        # self.live_servers_cnt_eq_initialization_server_cnt=0

        self.server_reply_metrics = {}
        self.client_request_metrics = {}

    # perform arp request when the system starts.
    # the arp floods all port but the incoming port.
    # after all arp requests are captured, the system
    # uses lldp packets to capture live_server events.
    # this is done to reduce the number of packets sent
    # on the network since arp floods all ports.
    def arp_request(self, s, protosrc, hwsrc):

        log.debug("performing arp request packet from %s to %s", protosrc.toStr(), s.toStr())

        # create arp object
        r = arp()
        # set arp object properties
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST  # destination mac address => ff:ff:ff:ff:ff:ff
        r.protodst = s  # destination ip
        # r.hwsrc = self.con.eth_addr     #switch mac address
        r.hwsrc = hwsrc  # switch mac address
        # r.protosrc = self.service_ip    #switch ip
        r.protosrc = protosrc  # switch ip
        e = ethernet(type=ethernet.ARP_TYPE, src=hwsrc,  # src=self.con.eth_addr,
                     dst=ETHER_BROADCAST)
        # attache arp (l3) to ethernet (l2)
        e.set_payload(r)
        # log.debug("ARPing for %s", s.toStr())
        # create packet and attach data to sent
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        # self.resend_packet(packet_in, of.OFPP_ALL)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = of.OFPP_NONE
        # send arp request
        self.con.send(msg)

    # handles connection up event, ie, ovs switch connects to pox controller.
    def _handle_ConnectionUp(self, event):

        # this is the port for poxbr:65534 at all times.
        prtCnt = len(self.con.ports)
        # find controller portnum

        # loop through all ovs switch ports. and find the controller port.
        for i in range(1, prtCnt):
            prt = self.con.ports[i]
            prtName = prt.name
            prtNum = prt.port_no
            macAdd = prt.hw_addr.toStr()
            # log.debug("ovs port name: %s - ovs port num: %s: - ovs port address  %s: ", prtName, prtNum, macAdd)
            if prtName == "vpcontroller":
                self.controller_prt = prtNum

        # build the arp table for the switch to know the mac address of each lb server on the network.
        self.arp_request_to_live_server()

        # this function will issue arp request as a loop periodically
        Timer(self.arp_timeout, self.arp_request_to_live_server, recurring=True)

        # this function will check for stale servers and remove old servers periodically. these
        # are servers which have not responded to arp request. each lb server have 3 chances to
        # response to arp request before being removed from network.
        Timer(self.server_timeout, self.remove_dead_servers_and_flows, recurring=True)

        # this function will check for stale flows and remove old flows periodically from pox controller.
        # this prevents the flow list from grown infinitelly large since they are not remove from the
        # pox controller automatically and a process needs to handle this aspect.
        Timer(self.server_client_flow_timeout, self.remove_expired_flows, recurring=True)

        Timer(self.arp_timeout + 3, self.build_clientip_index_table, recurring=False)

        Timer(20, self.wrtie_loadbalancer_metric_to_file, recurring=True)

        # f = open("/root/Documents/serverMetrics.txt", "w")
        # f.write("**************************************************************************/n")
        # f.close()

        # f = open("/root/Documents/clientMetrics.txt", "w")
        # f.write("**************************************************************************/n")
        # f.close()

    def wrtie_loadbalancer_metric_to_file(self):

        if len(self.server_reply_metrics) > 0:
            f = open("/root/Documents/serverMetrics.txt", "w")
            f.write("**************************************************************************\n")
            for sIP in self.server_reply_metrics:
                f.write("ip:" + sIP.toStr() + ":hits:" + str(self.server_reply_metrics[sIP]['hits']) + "\n")

            f.close()

        if len(self.client_request_metrics) > 0:
            f = open("/root/Documents/clientMetrics.txt", "w")
            f.write("**************************************************************************\n")
            for sIP in self.client_request_metrics:
                f.write("ip:" + sIP.toStr() + ":hits:" + str(self.client_request_metrics[sIP]['hits']) + "\n")
            f.close()

    # maps clientip to lb servers and store them in a table for indexing.
    def build_clientip_index_table(self):

        self.predefined_client_key.clear()
        # 2                              10
        for x in range(self.predefined_client_key_low_network, self.predefined_client_key_heigh_network):
            for y in range(1, 255):
                clientip = IPAddr("192.168." + str(x) + "." + str(y))
                if self.alg == "sourcehashing":
                    hashedIP = self.source_hashing(clientip)
                self.predefined_client_key[clientip] = hashedIP
                log.debug("Building client ip index table. clientip: %s mapped to serverip:%s", clientip, hashedIP)

    # perform arp request to live servers from the switch
    def arp_request_to_live_server(self):

        # loop through all servers and teach them the switch mac address
        for s in self.servers:
            self.arp_request(s, self.service_ip, self.con.eth_addr)

    # remove stale flows which have not be reused in some time.
    def remove_expired_flows(self):

        # check that the live server table contains servers ip
        if len(self.live_servers) == 0:
            return

        now = time.time()

        # loop through servers ip
        for sIP, prop in self.live_servers.items():
            # remove servers ip which have not responded to arp/lldp request in a long time(self.server_timeout)

            if sIP in self.sys_flow[self.con.dpid]:
                serverFlows = self.sys_flow[self.con.dpid][sIP]
                src = serverFlows.source
                sMac = src.mac
                sPrt = src.port

                for dst in serverFlows.destination:
                    if dst.updatedTime + self.server_client_flow_timeout < now:
                        serverIP = dst.ip
                        serverMac = dst.mac
                        serverPrt = dst.port

                        # remove the flows for the expired server from the ovs switch
                        # these comes in pairs (request/response)
                        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                        match = of.ofp_match()
                        match.dl_src = serverMac
                        match.dl_dst = self.service_mac
                        match.nw_src = serverIP
                        match.nw_dst = self.service_ip
                        match.dl_type = 0x800
                        match.nw_proto = 6
                        match.in_port = serverPrt
                        msg.match = match
                        self.con.send(msg)

                        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                        match = of.ofp_match()
                        match.dl_src = sMac
                        match.dl_dst = self.service_mac
                        match.nw_src = sIP
                        match.nw_dst = serverIP
                        match.dl_type = 0x800
                        match.nw_proto = 6
                        match.in_port = sPrt
                        msg.match = match
                        self.con.send(msg)

                        del self.sys_flow[self.con.dpid][serverIP]

                        self.sys_flow[self.con.dpid][sIP].destination.remove(dst)

                        log.debug("Expired flows have been removed")

        # if len(self.sys_flow[self.con.dpid]) < 5:
        #    log.debug("test breakpoint")

    # Remove dead servers flows
    def remove_dead_servers_and_flows(self):

        # check that the live server table contains servers ip
        if len(self.live_servers) == 0:
            return

        now = time.time()

        # loop through servers ip
        for sIP, prop in self.live_servers.items():
            # remove servers ip which have not responded to arp/lldp request in a long time(self.server_timeout)
            if self.live_servers[sIP]['serverTm'] + self.server_timeout < now:
                # log.info('server %s expired %s', sIP, self.live_servers[sIP])
                sMac = prop['serverMac']
                sPrt = self.live_servers[sIP]['serverPrt']

                if len(self.sys_flow[self.con.dpid]) > 0 and sIP in self.sys_flow[self.con.dpid]:
                    # loop through all the flows for the lb server that is dead and remove the flows from the pox controller cache and from the ovs switch.
                    for delFlow in (self.sys_flow[self.con.dpid][sIP]).destination:

                        serverIP = delFlow.ip
                        serverMac = delFlow.mac
                        serverPrt = delFlow.port

                        if serverIP in self.sys_flow[self.con.dpid]:
                            clientMachine = self.sys_flow[self.con.dpid][serverIP].source
                            if serverMac == clientMachine.mac and serverPrt == clientMachine.port:
                                # remove the flows for the expired server from the ovs switch
                                # these comes in pairs (request/response)
                                msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                                match = of.ofp_match()
                                match.dl_src = serverMac
                                match.dl_dst = self.service_mac
                                match.nw_src = serverIP
                                match.nw_dst = self.service_ip
                                match.dl_type = 0x800
                                match.nw_proto = 6
                                match.in_port = serverPrt
                                msg.match = match
                                self.con.send(msg)

                                msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                                match = of.ofp_match()
                                match.dl_src = sMac
                                match.dl_dst = self.service_mac
                                match.nw_src = sIP
                                match.nw_dst = serverIP
                                match.dl_type = 0x800
                                match.nw_proto = 6
                                match.in_port = sPrt
                                msg.match = match
                                self.con.send(msg)

                                # remove flow from the pox controller cache table for the dead server
                                del self.sys_flow[self.con.dpid][serverIP]

                    # log.debug("server")

                    # delete the server flow from pox
                    del self.sys_flow[self.con.dpid][sIP]

                    # remove dead server from the system since it did not reply to arp requests in 3 different occasions.
                del self.live_servers[sIP]

                # re-index the client hash keys since a server has been removed from the network
                self.build_clientip_index_table()

                log.debug("server %s has been removed from the system.", sIP.toStr())
                log.debug("Its client flow entries also have been removed from the system.")
                log.debug("The client ip index table has been recomputed.")
            # else:    #nothing to be done, server responded on time.
            #    log.debug("server %s is up : %s", sIP, self.live_servers[sIP])

            # log.debug("removal end")

    # handle lldp packets
    def lldp_packets(self, packet, inport):
        # log.debug("LLDP packets")
        # log.debug("Time: %s", time.time())

        lldp_p = packet.payload

        sysName = lldp_p.tlvs[3].payload
        sysPortName = lldp_p.tlvs[8].payload
        sysMac = packet.src
        sysIP = IPAddr(lldp_p.tlvs[6].address)

        self.update_server_timestamp(sysIP, sysMac, inport)

    # adding server to load balancer
    def add_server(self, sysIP, sysMac, inport):

        # log.debug("checking ip %s in liveservers", sysIP)
        if sysIP not in self.live_servers and sysIP in self.servers:
            addedtime = time.time()
            self.live_servers[sysIP] = {"serverMac": sysMac, "serverPrt": inport, "serverTm": addedtime}
            log.debug("server added to liveserver %s at %s", sysIP, addedtime)

            # self.live_servers_cnt_eq_initialization_server_cnt = self.live_servers_cnt_eq_initialization_server_cnt + 1
            # if self.live_servers_cnt_eq_initialization_server_cnt >= len(self.servers)+1:
            # self.build_clientip_index_table()
        # elif sysIP not in self.servers:
        #    log.debug("lb server is invalid %s", sysIP)
        # else:
        #    log.debug("server %s already exist in liveserver", sysIP)

    # update server timestamp
    def update_server_timestamp(self, sysIP):
        if sysIP in self.live_servers and sysIP in self.servers:
            # update server time
            now = time.time()
            # log.debug("server previous timestamp %s", self.live_servers[sysIP])
            self.live_servers[sysIP]['serverTm'] = now
            # log.debug("server current timestamp %s", self.live_servers[sysIP])
            return

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

    def get_sysFlow(self, clientip):

        if self.sys_flow[self.con.dpid][clientip] is not None:
            return self.sys_flow[self.con.dpid][clientip]
        return None

    def get_destination(self, clientip, dir):

        if self.sys_flow[self.con.dpid][clientip] is not None:
            sys_flow = self.sys_flow[self.con.dpid][clientip]
            if sys_flow.dir == dir:
                destination = sys_flow.destination
                if destination is not None:
                    return destination
        return None

        # this function adds flows for the clients and server. clients have only one flow match.

    # servers have a flow match list, that is, for each client ip there is a flow match
    # under the server for the client.
    def add_sysflow(self, machine, dir, idleTime, hardTime, machine2=None):

        clientip = machine.ip
        if dir == 0:
            # this is a client request
            # add a pox flow for the client performing the request.
            # find the server that needs to handle the request either from the cache table or generate the server ip that should handle the request.
            if clientip in self.predefined_client_key:
                sIP = self.predefined_client_key[clientip]
                # sIP=IPAddr("192.168.0.192")
            else:
                if self.alg == "sourcehashing":
                    sIP = self.source_hashing(clientip)
                    # sIP=IPAddr("192.168.0.192")

            sIPDetails = self.live_servers[sIP]
            servermac = sIPDetails['serverMac']
            serverPort = sIPDetails['serverPrt']
            serverMachine = Machine(sIP, servermac, serverPort, time.time())
            # the flowMatch object is a list object. clients only have one flow match in the list
            # flowMatch=[FlowMatch(serverMachine, self.flow_idle_time, self.flow_hard_time)] delb
            # flowMatch=[FlowMatch(serverMachine)]
            self.sys_flow[self.con.dpid][clientip] = SysFlow(machine, [serverMachine], dir, idleTime, hardTime)
        else:
            # this is a client response
            # add a pox flow for the lb server.
            sIP = machine2.ip
            servermac = machine2.mac
            serverPort = machine2.port
            destinationtMachine = Machine(sIP, servermac, serverPort, time.time())
            flowNotInServer = False
            # the destination object is a list object. servers have a list of flow match that belongs to the different clients which hit the server.
            # these matches are expired from ovs after x time if client does not hit the server
            # these matches are expired from pox after x time if client does not hit the server
            # pox time is greater than ovs time.
            if clientip not in self.sys_flow[self.con.dpid]:
                self.sys_flow[self.con.dpid][clientip] = SysFlow(machine, [destinationtMachine], dir, idleTime,
                                                                 hardTime)
            elif len(self.sys_flow[self.con.dpid]) > 0:
                for m in (self.sys_flow[self.con.dpid][clientip]).destination:
                    if m.ip == sIP:
                        flowNotInServer = True

                # append flow to lb server.
                if flowNotInServer == False:
                    (self.sys_flow[self.con.dpid][clientip]).destination.append(destinationtMachine)

            # if len(self.sys_flow[self.con.dpid]) > 10:
            # log.debug("test breakpoint")

        # log.debug("lb server handling request %s - 88888888888888888888888888888886666666666666666666666", sIP.toStr())

        return self.sys_flow[self.con.dpid][clientip]

    def _handle_PacketIn(self, event):

        now = time.time()
        # log.debug("current time is: %s", now)

        inport = event.port
        packet = event.parsed
        packet_in = event.ofp

        # check is lldp packet
        if packet.type == ethernet.LLDP_TYPE and self.arp_timer != SH_LoadBalancing.ARP_TIMER:
            # log.debug("capturing lldp packet")
            self.lldp_packets(packet, inport)
            if SH_LoadBalancing.TIMER_SET == 0 and self.lldp_timer == SH_LoadBalancing.LLDP_TIMER:
                SH_LoadBalancing.TIMER_SET = 1
                Timer(self.server_timeout, self.remove_dead_servers_and_flows, recurring=True)

        # checking if an arp packet
        elif isinstance(packet.next, arp) and self.lldp_timer != SH_LoadBalancing.LLDP_TIMER:
            p = packet.next

            if p.protosrc == p.protodst:
                return

            # you received an arp reply, update the liveserver time for the current server ip
            if p.opcode == arp.REPLY:
                log.debug("capturing arp reply packet from %s to %s", p.protosrc, p.protodst)

                # the reply is captured here and add server ip to self.live_servers and update server timestamp if server is not in live_servers object list.
                self.add_server(p.protosrc, p.hwsrc, inport)
                self.update_server_timestamp(p.protosrc)
        # tcp packet
        elif packet.type == ethernet.IP_TYPE and packet.next.protocol == packet.next.TCP_PROTOCOL:
            dstip = packet.next.dstip
            dstmac = packet.dst
            dstport = packet.next.next.dstport
            srcip = packet.next.srcip
            srcmac = packet.src

            # tcp packet response
            # lb server is reaching out to client. install entry flow for the server to client communication
            # handles http response
            if dstip != self.service_ip and len(self.live_servers) > 0 and dstip not in self.live_servers:

                packet = event.parsed

                if len(self.sys_flow[self.con.dpid]) == 0:
                    log.debug("**********************Did not know how to handle this request.**********************")
                    return;

                # client needs to resend request again and install a flow entry for the client first.
                # this could happen if the live server is removed from the lb system between the time
                # that the client placed the 1st request and reaches out again to the server.
                destinationip = packet.next.dstip
                if self.sys_flow[self.con.dpid][destinationip] is None:
                    log.debug("**********************Client flow was removed and cannot continue**********************")
                    return

                sourceip = packet.payload.srcip
                sourcemac = packet.src
                sourceport = inport
                # create a client object
                sourceMachine = Machine(sourceip, sourcemac, sourceport, time.time())

                httpResponseExists = False
                # check if the lb server performing the response contains a flow on pox controller
                # if it does, reuse the flow
                if len(self.sys_flow[self.con.dpid]) > 0 and self.sys_flow[self.con.dpid].get(sourceip) is not None:
                    sysFlowSrc = self.sys_flow[self.con.dpid].get(sourceip)
                    sys_flow = self.sys_flow[self.con.dpid].get(sourceip)
                    if sys_flow.dir == 1:
                        i = 0
                        for dstObj in sys_flow.destination:
                            if dstObj.ip == dstip:
                                # there is a flow match that exists. don't create one from scratch, use the one that is stored on the table.
                                destination = dstObj
                                sysflow = self.get_sysFlow(sourceip)
                                sys_flow.destination[i].updatedTime = time.time()
                                httpResponseExists = True
                                break
                            i = i + 1

                # the lb server does not contain a flow object on pox. create a flow object for the server
                if httpResponseExists == False:
                    # either the client have not performed flow entries before, or
                    # flow entry has expired from ovs switch  and lb flow table.
                    # we need to create a flow entry in the ovs switch and lb flow table.

                    if destinationip in self.sys_flow[self.con.dpid]:
                        sysFlowSrc = self.sys_flow[self.con.dpid].get(destinationip)
                        if sysFlowSrc.dir == 0:
                            clientMachine = sysFlowSrc.source
                            sys_flow = self.add_sysflow(sourceMachine, 1, self.flow_idle_time, self.flow_hard_time,
                                                        clientMachine)
                            for dst in sys_flow.destination:
                                if dst.ip == destinationip:
                                    destination = dst

                # pull client port and mac address from the client flow table
                destinationmac = destination.mac
                destinationport = destination.port
                # flowMatch=self.get_sysflow(destinationip, 0)

                # set flow entry actions and match condition for the ovs switch.
                actions = []
                actions.append(of.ofp_action_dl_addr.set_src(self.con.eth_addr))
                actions.append(of.ofp_action_dl_addr.set_dst(destinationmac))
                actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
                actions.append(of.ofp_action_nw_addr.set_dst(dstip))
                actions.append(of.ofp_action_output(port=destinationport))
                # match = of.ofp_match.from_packet(packet, inport)

                match = of.ofp_match()
                match.dl_type = 0x800
                match.nw_proto = 6
                match.in_port = inport
                match.dl_src = sourceMachine.mac
                match.nw_src = sourceMachine.ip
                match.dl_dst = self.con.eth_addr
                match.nw_dst = destinationip

                msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                      # idle_timeout=flowMatch[0].idleTime*6*60,  delb
                                      idle_timeout=sys_flow.idleTime * 6 * 60,
                                      hard_timeout=of.OFP_FLOW_PERMANENT,
                                      priority=45535,
                                      data=event.ofp,
                                      actions=actions,
                                      match=match)
                self.con.send(msg)
                # log.debug("test")

                if sourceip in self.server_reply_metrics:
                    self.server_reply_metrics[sourceip]['hits'] = self.client_request_metrics[sourceip]['hits'] + 1
                else:
                    self.server_reply_metrics[sourceip] = {"hits": 1}

                log.debug("stop")
                # tcp packet request
            # client is reaching out to server. install entry flow for the client to server communication
            # handles http request
            elif dstip == self.service_ip and len(self.live_servers) > 0:

                # time.sleep(0.5)

                packet = event.parsed
                # now = time.time()
                # get client info
                sourceip = packet.payload.srcip
                sourcemac = packet.src
                sourceport = inport
                # create a client object
                sourceMachine = Machine(sourceip, sourcemac, sourceport, time.time())

                # there are no flow entries at all saved on ovs and/or lb server flow table
                if len(self.sys_flow[self.dpid]) == 0:

                    sysflow = self.add_sysflow(sourceMachine, 0, self.flow_idle_time, self.flow_hard_time)
                    destination = sysflow.destination[0]
                    # serverMachine= destination[0]
                    # log.debug("lb server handling request %s - 6666666666666666666666666666666666", sourceip.toStr())
                    # (self.sys_flow[self.con.dpid][IPAddr("192.168.0.6")]).

                # the system has flow entries
                elif len(self.sys_flow[self.dpid]) > 0:
                    # if the client placed requests before and the flow entry is in the sys_flow table.
                    # this will happend if the flow entry expired from the ovs switch and not from the lb flow table
                    key = self.sys_flow[self.con.dpid].get(sourceip)
                    if key is not None:
                        sysflow = self.get_sysFlow(sourceip)
                        destination = self.get_destination(sourceip, 0)[0]
                        sysflow.source.updatedTime = time.time()
                    else:
                        # either the client have not performed flow entries before, or
                        # flow entry has expired from ovs switcha and lb flow table.
                        # we need to create a flow entry in the ovs switch and lb flow table.
                        sysflow = self.add_sysflow(sourceMachine, 0, self.flow_idle_time, self.flow_hard_time)
                        destination = sysflow.destination[0]
                        # serverMachine=flowMatch.serverMachine
                        # there are no flow entries saved for the client

                # for m in self.sys_flow[self.con.dpid]:
                #    log.debug("you have flow %s @@@@@@@@@@@@@@@@@@@@@@@@@@@@@", self.sys_flow[self.con.dpid][m].source.ip.toStr() )

                packet = event.parsed

                actions = []
                actions.append(of.ofp_action_dl_addr.set_src(sourcemac))
                actions.append(
                    of.ofp_action_dl_addr.set_dst(destination.mac.toStr()))  # dst server to handle request: mac
                actions.append(of.ofp_action_nw_addr.set_src(sourceip))
                actions.append(of.ofp_action_nw_addr.set_dst(
                    destination.ip.toStr()))  # dst server to handle request: ip
                actions.append(of.ofp_action_output(port=destination.port))  # dst server to handle request:sw prt
                # match = of.ofp_match.from_packet(packet, inport)                #inport => event.port

                # match = of.ofp_match.from_packet()

                # connection.send( of.ofp_flow_mod(action=of.ofp_action_output(port=2),priority=32,
                # match=of.ofp_match(dl_type=0x800,nw_src="10.0.0.1",nw_dst="10.0.0.2")))

                match = of.ofp_match()
                match.dl_type = 0x800
                match.nw_proto = 6
                match.in_port = inport
                match.dl_src = sourcemac
                match.nw_src = sourceip
                match.dl_dst = self.service_mac
                match.nw_dst = self.service_ip
                # match.dl_vlan=0x0000
                # match.tp_dst=80

                msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                      # idle_timeout=flowMatch[0][0].idleTime*6*60,
                                      idle_timeout=sysflow.idleTime * 6 * 60,
                                      hard_timeout=of.OFP_FLOW_PERMANENT,
                                      priority=45535,
                                      # vlan_tci=0x0000,
                                      data=event.ofp,
                                      actions=actions,
                                      match=match)

                self.con.send(msg)

                if sourceip in self.client_request_metrics:
                    self.client_request_metrics[sourceip]['hits'] = self.client_request_metrics[sourceip]['hits'] + 1
                else:
                    self.client_request_metrics[sourceip] = {"hits": 1}

                log.debug("stop")
                # log.debug("stop2")
        # else:
        #    log.debug("another type of traffic")


def launch(reactive=False):
    def loadbalancing_start(event):
        log.debug("Controlling %s" % (event.connection,))
        core.registerNew(SH_LoadBalancing, event.connection, service_ip="192.168.0.11",
                         servers=["192.168.0.64", "192.168.0.128", "192.168.0.192", "192.168.0.254"],
                         alg="sourcehashing", arp_timer=1, lldp_timer=0)
        event.connection.addListeners(core.SH_LoadBalancing)

    core.openflow.addListenerByName("ConnectionUp", loadbalancing_start)
