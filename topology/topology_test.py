
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing
import time


topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):
    # You can automate some tests here
    result = []
    h1, h2, h3, h4 = net.get("h1"), net.get("h2"), net.get("h3"), net.get("h4")
    ws1, ws2, ws3 = net.get("ws1"), net.get("ws2"), net.get("ws3")
    lb1 = net.get('lb1')

    public_hosts = {h1, h2}
    private_hosts = {h3, h4}
    servers = {ws1, ws2, ws3}
    all_hosts = {h1, h2, h3, h4}

    all_nodes = [h1,h2,h3,h4,ws1,ws2,ws3,lb1]


    def ping_connectivity():
        print("")
        print("Ping connectivity ([Y]es/[N]o)")

        # Print column headers
        print("    ", end="")
        for i in range(8):
            print("{:>4}".format(all_nodes[i].name), end="")
        print("")

        # Print host connectivity
        for i in range(8):
            print("{:<4}".format(all_nodes[i].name), end="")
            for j in range(8):
                connective = testing.ping(all_nodes[i],all_nodes[j].IP(),True)        
                if connective:
                    print("{:>4}".format("Y"), end="")
                else:
                    print("{:>4}".format("N"), end="")
            print("")


    def public_ping_private():
        #  public_Host ping private_IP
        for h_pb in public_hosts:
            for h_pr in private_hosts:
                if testing.ping(h_pb, h_pr.IP(), False):
                    print("  correct: %s in PbZ cannot ping %s in PrZ"% (h_pb.name, h_pr.IP()))
                    result.append(True)
                else:
                    print("incorrect: %s in PbZ can ping %s in PrZ"% (h_pb.name, h_pr.IP()))
                    result.append(False)


    def private_ping_public():
        #  private_Host to public_IP
        for pr in private_hosts:
            for pb in public_hosts:
                if testing.ping(pr, pb.IP(), True):
                    print("  correct: %s in PrZ can ping %s in PbZ"% (pr.name, pb.IP()))
                    result.append(True)
                else:
                    print("incorrect: %s in PrZ cannot ping %s in PbZ"% (pr.name, pb.IP()))
                    result.append(False)


    def ping_ws():
        #  all host ping server
        for h in all_hosts:
            for s in servers:
                if testing.ping(h, s.IP(), False):
                    print("  correct: %s cannot ping %s in DmZ"% (h.name, s.IP()))
                    result.append(True)
                else:
                    print("incorrect: %s can ping %s in DmZ"% (h.name, s.IP()))
                    result.append(False)

    def ping_lb1():
        #  all host ping server
        for h in all_hosts:
                if testing.ping(h, lb1.IP(), True):
                    print("  correct: %s can ping 100.0.0.45 lb1"% (h.name))
                    result.append(True)
                else:
                    print("incorrect: %s cannot ping 100.0.0.45 lb1"% (h.name))
                    result.append(False)


    def ws_ping_public():
        # server ping public host
        for s in servers:
            for pb in public_hosts:
                if testing.ping(s, pb.IP(), False):
                    print("  correct: %s cannot ping %s in PbZ"% (s.name, pb.IP()))
                    result.append(True)
                else:
                    print("incorrect: %s can ping %s in PbZ"% (s.name, pb.IP()))
                    result.append(False)


    def ws_ping_private():
        # server ping private host
        for s in servers:
            for pr in private_hosts:
                if testing.ping(s, pr.IP(), False):
                    print("  correct: %s cannot ping %s in PrZ"% (s.name, pr.IP()))
                    result.append(True)
                else:
                    print("incorrect: %s can ping %s in PrZ"% (s.name, pr.IP()))
                    result.append(False)



    def curl_with_payload_put_other():
        # host curl server with payload
        for h in all_hosts:
            if testing.curl(h, "100.0.0.45",method = "PUT",payload= "other", expected=True):
                print("  correct: %s from PrZ can curl lb1 with PUT and payload:other"% (h.name))
                result.append(True)
            else:
                print("  incorrect: %s from PrZ cannot curl lb1 with PUT and payload:other"% (h.name))
                result.append(False)

    def curl_with_payload_put_UPDATE():
        # host curl server with payload
        for h in all_hosts:
            if testing.curl(h, "100.0.0.45",method = "PUT",payload= "UPDATE", expected=False):
                print("  correct: %s from PrZ cannot curl lb1 with PUT and payload:UPDATE"% (h.name))
                result.append(True)
            else:
                print("  incorrect: %s from PrZ can curl lb1 with PUT and payload:UPDATE"% (h.name))
                result.append(False)

    def curl_with_payload_get():
        # host curl server with payload
        for h in all_hosts:
            if testing.curl(h, "100.0.0.45",method = "GET", expected=False):
                print("  correct: %s from PrZ cannot curl lb1 with GET"% (h.name))
                result.append(True)
            else:
                print("  incorrect: %s from PrZ can curl lb1 with GET"% (h.name))
                result.append(False)

    def curl_with_payload_post_other():
        # host curl server with payload
        for h in all_hosts:
            if testing.curl(h, "100.0.0.45",method = "POST",payload= "other", expected=True):
                print("  correct: %s from PrZ can curl lb1 with POST with payload:other"% (h.name))
                result.append(True)
            else:
                print("  incorrect: %s from PrZ cannot curl lb1 with POST with payload:other"% (h.name))
                result.append(False)

    ping_connectivity()
    print("")

    public_ping_private()
    private_ping_public()
    ping_ws()
    ping_lb1()
    ws_ping_public()
    ws_ping_private()

    
    curl_with_payload_put_other()
    curl_with_payload_put_UPDATE()

    curl_with_payload_get()
    curl_with_payload_post_other()


    print("")
    print("---------------FINAL RESULT---------------")
    if all(result):
        print("Correct: All tests finished as expected")
    else:
        print("Incorrect: Some tests finished with an error")
    print("")

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

    
    time.sleep(2)
    run_tests(net)


    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###

    net.stop()
