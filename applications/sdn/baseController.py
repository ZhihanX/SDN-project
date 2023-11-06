from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from networkFirewalls import FW1, FW2
import webserver
import subprocess
import shlex
import datetime
import click_wrapper
from forwarding import l2_learning

log = core.getLogger()

class L2_Learning (l2_learning.LearningSwitch):

    def __init__(self, connection, name):
        super(L2_Learning, self).__init__(connection, transparent=False)
        self.name = name
        self.dpid = connection.dpid

    def _handle_PacketIn(self, event):
        packet = event.parsed
        
        if not packet.parsed:
            log.warning(self.name, ": Incomplete packet received! controller ignores that")
            return

        core.controller.updatefirstSeenAt(packet.src, f"{self.name} - switch {event.connection.dpid} - port {event.port}")
        super(L2_Learning, self)._handle_PacketIn(event)

class controller (object):
    # Here you should save a reference to each element:
    devices = dict()

    # Here you should save a reference to the place you saw the first time a specific source mac
    firstSeenAt = dict()

    def __init__(self):

        webserver.webserver(self)
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        """
        This function is called everytime a new device starts in the network.
        We determine a device is a firewall based on its dpid,
        then execute the correct firewall application on it.
        
        For all other switches we use the provided l2_learning module.
        """

        # In phase 2, you will need to run your network functions on the controller. Here is just an example how you can do it (Please ignore this for phase 1):
        # click = click_wrapper.start_click("../nfv/forwarder.click", "", "/tmp/forwarder.stdout", "/tmp/forwarder.stderr")

        if(event.dpid < 5):
            l2_switch = L2_Learning(event.connection, f"switch {event.dpid}")
            self.devices[l2_switch.dpid] = l2_switch
        
        elif(event.dpid == 5):
            # FW1(event.connection)
            firewall_1 = FW1(event.connection)
            self.devices[firewall_1.dpid] = firewall_1

        elif(event.dpid == 6):
            # FW2(event.connection)
            firewall_2 = FW2(event.connection)
            self.devices[firewall_2.dpid] = firewall_2
        elif(event.dpid == 7):
            # Start Click for IDS
            click = click_wrapper.start_click("./applications/nfv/ids.click", "", "/tmp/ids.stdout", "/tmp/ids.stderr")
        
        elif(event.dpid == 8):
            # Start Click for lb1
            click = click_wrapper.start_click("./applications/nfv/lb1.click", "", "/tmp/lb1.stdout", "/tmp/lb1.stderr")
          
            #Start Forwarder for lb1
            # click = click_wrapper.start_click("./applications/nfv/lb1-fwd.click", "", "/tmp/lb1.stdout", "/tmp/lb1.stderr")

        elif(event.dpid == 9):
            # Start Click for napt
            click = click_wrapper.start_click("./applications/nfv/napt.click", "", "/tmp/napt.stdout", "/tmp/napt.stderr")

            # Start Forwarder for NAPT
            # click = click_wrapper.start_click("./applications/nfv/napt-fwd.click", "", "/tmp/napt.stdout", "/tmp/napt.stderr")

        else:
            print("Not started dpid: " +str(event.dpid))

        return

    # This should be called by each element in your application when a new source MAC is seen
    def updatefirstSeenAt(self, mac, where):
        """
        This function updates your first seen dictionary with the given input.
        It should be called by each element in your application when a new source MAC is seen
        """

        # Check if MAC address is already in firstSeenAt dictionary
        if not mac in self.firstSeenAt:
            self.firstSeenAt[mac] = (where, datetime.datetime.now().isoformat())

        return


    def flush(self):
        """
        This is called by the webserver and acts as a 'soft restart'. It:
        1) asks the switches to flush the rules
        2) clears the mac learning table in each l2_learning switch (Python side) 
        3) clears the firstSeenAt dictionary
        """
        # Delete all OpenFlow rules for each switch
        for connection in core.openflow._connections.values():
            msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
            connection.send(msg)
            
        # Clear MAC learning table in each network component
        for component in self.devices.values():
            component.macToPort.clear()
                
        # Clear firstSeenAt dictionary
        self.firstSeenAt.clear()

        return


def launch(configuration=""):
    core.registerNew(controller)
