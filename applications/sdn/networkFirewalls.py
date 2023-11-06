from baseFirewall import Firewall


# Here we implement our network firewalls. All network firewalls are inherited from Firewall class.

# Rules parameters are:
# index 0: Determines the hardware port of the incoming packet.
# index 1: Determines the TCP layer protocol. (possible values: TCP, UDP, any)
# index 2: Determine the source IP address of the incoming packet. It should be either "any" or a subnet with "IP/Subnet" format (e.g, 100.0.0.40/32).
# index 3: Determine the TCP layer source port number of the incoming packet. (possible values: any, an integer as the port number)
# index 4: Determine the destination IP address of the incoming packet. Same format as the source IP.
# index 5: Determine the TCP layer destination port number of the incoming packet. Same format as the source port.
# index 6: To allow or block the matched packet. (possible values: allow, block)

# Note that the Firewall trace the rules from 0 to n and make the decision based on first matched rule.

# Hardware ports:
# public-zone --------- 1 FW1 2 ------------ DmZ
# DmZ ----------------- 1 FW2 2 ------------ private-zone

# Subnet 100.0.0.32/28 has 13 usable hosts, from 100.0.0.34 to 100.0.0.46

class FW1 (Firewall):

    def __init__(self, connection):

        """
        Initialize Firewall 1
        FW1 allows TCP traffic to port 80 in the DmZ,
        blocks all other traffic from the PbZ,
        and allows outgoing traffic from the PrZ and DmZ.
        """

        Firewall.__init__(self, connection, "FW1")
        self.rules = [
            # Allow TCP traffic to port 80 in 100.0.0.32/28
            [1, 'TCP', 'any', 'any', '100.0.0.32/28', '80', 'allow'],
            # Allow Pings from PbZ to 100.0.0.45
            [1, 'any', 'any', 'any', '100.0.0.45/32', 'any', 'allow'],
            # Block new connections from PbZ
            [1, 'any', 'any', 'any', 'any', 'any', 'block'],
            # Allow all traffic from PrZ and DmZ
            [2, 'any', 'any', 'any', 'any', 'any', 'allow']
        ] 

class FW2 (Firewall):
    def __init__(self, connection):

        """
        Initialize Firewall 2
        FW2 only allows TCP traffic to port 80 to the DmZ,
        all traffic from the PrZ to anything other than the DmZ,
        and blocks all incoming traffic to PrZ.
        """

        Firewall.__init__(self, connection, "FW2")
        self.rules = [
            # Only allow TCP to port 80 to DMZ and ping to 100.0.0.45
            [2, 'TCP', 'any', 'any', '100.0.0.32/28', '80', 'allow'],
            [2, 'any', 'any', 'any', '100.0.0.45/32', 'any', 'allow'],
            [2, 'any', 'any', 'any', '100.0.0.32/28', 'any', 'block'],
            # Allow all other traffic from PrZ
            [2, 'any', 'any', 'any', 'any', 'any', 'allow'],
            # Block all other traffic from DMZ, PbZ
            [1, 'any', 'any', 'any', 'any', 'any', 'block']
        ]