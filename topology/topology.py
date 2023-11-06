
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch


class MyTopo(Topo):
    def __init__(self):

        # Initialize topology
        Topo.__init__(self)

        # Here you initialize hosts, web servers and switches
        # (There are sample host, switch and link initialization,  you can rewrite it in a way you prefer)
        ### COMPLETE THIS PART ###

        # Initialize hosts
        ## PbZ
        h1 = self.addHost('h1', ip='100.0.0.10/24', defaultRoute='via 100.0.0.1')
        h2 = self.addHost('h2', ip='100.0.0.11/24', defaultRoute='via 100.0.0.1')
        ## PrZ
        h3 = self.addHost('h3', ip='10.0.0.50/24', defaultRoute='via 10.0.0.1')
        h4 = self.addHost('h4', ip='10.0.0.51/24', defaultRoute='via 10.0.0.1')

    
        # Initialize servers
        ws1 = self.addHost('ws1', ip='100.0.0.40/24')
        ws2 = self.addHost('ws2', ip='100.0.0.41/24')
        ws3 = self.addHost('ws3', ip='100.0.0.42/24')

        # Initial switches
        sw1 = self.addSwitch('sw1', dpid="1")
        sw2 = self.addSwitch('sw2', dpid="2")
        sw3 = self.addSwitch('sw3', dpid="3")
        sw4 = self.addSwitch('sw4', dpid="4")

        # Initialize firewalls
        fw1 = self.addSwitch('fw1', dpid="5")
        fw2 = self.addSwitch('fw2', dpid="6")

        # Initialize NFV nodes
        insp = self.addHost('insp', ip='100.0.0.30/24')
        ids  = self.addSwitch('ids',  dpid="7")
        lb1  = self.addSwitch('lb1',  dpid="8")
        napt = self.addSwitch('napt', dpid="9")


        # Defining links
        # Public zone
        self.addLink(h1, sw1)
        self.addLink(h2, sw1)
        self.addLink(sw1, fw1)

        # Demilitarized Zone
        ## Zone interonnect
        self.addLink(fw1, sw2)
        self.addLink(sw2, fw2)

        ## SW2 to SW4
        self.addLink(sw2, ids)
        self.addLink(ids, lb1)
        self.addLink(lb1, sw4)
        self.addLink(ids, insp)

        ## SW4 to servers
        self.addLink(sw4, ws1)
        self.addLink(sw4, ws2)
        self.addLink(sw4, ws3)
        
        # Private zone
        self.addLink(fw2, napt)
        self.addLink(napt, sw3)
        self.addLink(h3, sw3)
        self.addLink(h4, sw3)

def disable_ipv6(net):
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    for sw in net.switches:
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

def startup_services(net):
    # Disable IPv6
    disable_ipv6(net)

    # Start http services on each webserver...
    for server in ["ws1", "ws2", "ws3"]:
        net.get(server).cmd("cd ./applications/sdn/webpages/; python3 -m http.server 80 &")


topos = {'mytopo': (lambda: MyTopo())}

if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)

    startup_services(net)
    # Start the network
    net.start()

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###

    net.stop()
