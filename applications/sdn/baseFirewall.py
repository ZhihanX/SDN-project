from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from forwarding import l2_learning
import pox.lib.packet as pkt

log = core.getLogger()
 
# This is the basic Firewall class which implements all features of your firewall!
# For upcoming packets, you should decide if the packet is allowed to pass according to the firewall rules (which you have provided in networkFirewalls file during initialization.)
# After processing packets you should install the correct OF rule on the device to threat similar packets the same way on dataplane (without forwarding packets to the controller) for a specific period of time.

# rules format:
# [input_HW_port, protocol, src_ip, src_port, dst_ip, dst_port, allow/block]
# Checkout networkFirewalls.py file for detailed structure.

class Firewall (l2_learning.LearningSwitch):

    rules = []

    def __init__(self, connection, name):
        """
        Initialization of the Firewall
        Here, we set the connection, device name and dpid.
        """

        super(Firewall, self).__init__(connection, False)
        self.connection = connection
        self.name = name
        self.dpid = connection.dpid


    def check_HW_port(self,input_port,HW_port):
        """
        Check if the rule and actual input port match.
        Returns True if they do, Fals otherwise.
        """
        if input_port == HW_port :
            return True
        else:
            return False


    def check_protocol(self,ip_packet,protocol):
        """
        Check protocol limitations given by the firewall rule.
        Return True if the protocol is correct, False otherwise.
        """

        ptc_tcp = ip_packet.find('tcp')
        ptc_udp = ip_packet.find('udp')
        
        if protocol  == 'any':
            return True
        if (ptc_tcp and protocol=='TCP') or (ptc_udp and protocol == 'UDP'):
            return True
        else:
            return False


    def check_src_subnet(self,ip_packet,src_subnet):
        """
        Return True if the ip_packet comes from an allowed source subnet,
        False otherwise.
        """
        if src_subnet == 'any' or ip_packet.srcip.inNetwork(src_subnet):
            return True
        else:
            return False


    def check_dst_subnet(self,ip_packet,dst_subnet):
        """
        Return True if the ip_packet goes to an allowed destination subnet,
        False otherwise.
        """
        if dst_subnet == 'any' or ip_packet.dstip.inNetwork(dst_subnet):
            return True
        else:
            return False


    def check_src_port(self,ip_packet,src_port):
        """
        If packet is TCP/UDP, return True if source port is allowed, False otherwise.
        If not return True.
        """
        transport = ip_packet.find('tcp')

        if not transport:
            transport = ip_packet.find('udp')

        if transport:
            if src_port == 'any' or int(src_port) == transport.srcport:
                return True
            else :
                return False
        else:
            return True


    def check_dst_port(self,ip_packet, dst_port):
        """
        If packet is TCP/UDP, return True if destination port is allowed, False otherwise.
        If not return True.
        """
        transport = ip_packet.find('tcp')
        
        if not transport:
            transport = ip_packet.find('udp')

        if transport:
            if dst_port == 'any' or int(dst_port) == transport.dstport:
                return True
            else :
                return False
        else:
            return True


    def has_access(self, ip_packet, input_port):
        """
        Check if the ip_packet from the inpur_port is allowed through the firewall.
        Called from _handle_PacketIn().
        Return True if the packet is allowed, False if not.
        Return None if no rule matches.
        Always return True for ARP.
        """
        if ip_packet.find('arp'):
            return True

        for rule in self.rules:
            input_HW_port, protocol, src_ip, src_port, dst_ip, dst_port, action = rule

            if (self.check_HW_port(input_port,input_HW_port) and 
                self.check_protocol(ip_packet,protocol) and 
                self.check_src_port(ip_packet,src_port) and 
                self.check_dst_port(ip_packet,dst_port) and
                self.check_src_subnet(ip_packet,src_ip) and
                self.check_dst_subnet(ip_packet,dst_ip)):

                    if action == 'allow':
                        return True
                    elif action == 'block':
                        return False
        return None
       

    # Install rule for reverse flow, once allowed
    def allow_reverse(self, packet, in_port):
        """
        Install temporary forwarding and reverse rule when allowing a flow through the firewall.
        """

        reverse_match = of.ofp_match.from_packet(packet,in_port).flip()
        reverse_match.nw_proto = None
        reverse_match.fix()
        
        if packet.dst in self.macToPort:
            # Set specific in_port if dst port known,
            reverse_match.in_port = self.macToPort[packet.dst]
        else:
            # If unknown set wildcard port (will be set on next rule installation)
            reverse_match.in_port = None
        
        log.debug("installing flow for %s.%s -> %s.%i" %
                  (packet.dst, str(reverse_match.in_port), packet.src, in_port))
        msg = of.ofp_flow_mod()
        msg.match = reverse_match
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = in_port))
        self.connection.send(msg)


    def block_traffic(self, packet):
        """
        Install an OF rule without an action => Block packets from this flow
        """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 1
        self.connection.send(msg)


    def _handle_PacketIn(self, event):
        """
        Handle incoming packets to the controller.
        Use L2-Forwarding if the packet is allowed through the Firewall.
        """

        packet = event.parsed
        
        if not packet.parsed:
            log.warning(self.name, ": Incomplete packet received! controller ignores that")
            return

        ip_packet =  packet.payload
        in_port = event.port
        core.controller.updatefirstSeenAt(packet.src, f"{self.name} - switch {event.connection.dpid} - port {event.port}")

        if self.has_access(ip_packet,in_port):
                # If the packet is allowed, allow it
                log.info("Allowing traffic from %s to %s at %s" % (packet.src, packet.dst, self.name))

                # Allow packet through, forward with l2_learning
                super(Firewall, self)._handle_PacketIn(event)
                
                # Install reverse rule, to allow response
                self.allow_reverse(packet ,in_port)

      
        else:
                # If the packet is not allowed, block it
                log.warning("Blocking traffic from %s to %s at %s" % (packet.src, packet.dst, self.name))
                self.block_traffic(packet)
