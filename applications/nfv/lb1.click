// 2 variables to hold ports names
// port1 is the inside ethernet port, port 2 is the outside ethernet port

// Conuters for report
InputCount_C, InputCount_S, OutputCount_C, OutputCount_S :: AverageCounter;
arpReqCount, arpReqCount1, arpQueCount, arpQueCount1, ipCount_C, ipCount_S, icmpCount,
icmpCount1, DisCountARP_C, DisCountIP_C, DisCountARP_S, DisCountIP_S :: Counter;

define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

//ARPResponder(IP/MASK [IP/MASK...] ETH, IP2/MASK2 ETH2, ...)
AddressInfo(
	Client	100.0.0.45/24  $PORT1,
	Server	100.0.0.45/24  $PORT2,
);
// Script will run as soon as the router starts
Script(print "Click LB1 on $PORT1 $PORT2")

// From where to pick packets
fd1:: FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true) //from client
fd2:: FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true) //from server

// Where to send packets
td1:: ToDevice($PORT1, METHOD LINUX) //to client
td2:: ToDevice($PORT2, METHOD LINUX) //to server

 //Instantiate 2 forwarders, 1 per directions
//fd1->fwd1::L2Forwarder($port1)->td2
//fd2->fwd2::L2Forwarder($port2)->td1

//Classifier for both client and server
ClientPacketClassifier, ServerPacketClassifier :: Classifier(
	12/0806 20/0001, //ARP requests to output 0
 	12/0806 20/0002, //ARP replies to output 1
 	12/0800, //IP packets to output 2
 	- // all other packets to output 3
)

//Classify packets from server
ipPacketClassifierClient :: IPClassifier(
	dst 100.0.0.45 and icmp, //icmp
	dst 100.0.0.45 port 80 and tcp, //tcp
	-  //all others
)

//Classify packets from client(PrZ PbZ)
ipPacketClassifierServer :: IPClassifier(
	dst 100.0.0.45 and icmp type echo, // ICMP to lb
	src port 80 and tcp, //tcp
	- //others
)

// two inputs for arpQuerier. 0 is for IP packet, 1 is for ARP reply which include Ethernet header.
arpQuerierClient :: ARPQuerier(Client)
arpQuerierServer :: ARPQuerier(Server)

//Forward an ARP reply if it can.
//one input should be ARP request packet including ethernet header.
arpRespondClient :: ARPResponder(Client)
arpRespondServer :: ARPResponder(Server)

toClient :: Queue -> OutputCount_C -> td1;
toServer :: Queue -> OutputCount_S -> td2;



ipPacketClient :: CheckIPHeader -> [0]arpQuerierClient -> toClient
ipPacketServer :: CheckIPHeader -> [0]arpQuerierServer -> toServer


roundRobinMap :: RoundRobinIPMapper(
	100.0.0.45 - 100.0.0.40 - 0 1,
	100.0.0.45 - 100.0.0.41 - 0 1,
	100.0.0.45 - 100.0.0.42 - 0 1
)

ipRewrite :: IPRewriter (roundRobinMap)



//ipRewrite has two outputs,0 for forward, 1 for reply.
//inputs maybe 0 for tcp, 1 for udp? not sure
ipRewrite[0] -> ipPacketServer
ipRewrite[1] -> ipPacketClient

//a packet from client(Port1)
fd1 -> InputCount_C -> ClientPacketClassifier

//0 for arp request, 1 for arp reply, 2 for IP, 3 for others
ClientPacketClassifier[0] -> arpReqCount -> arpRespondClient -> toClient
ClientPacketClassifier[1] -> arpQueCount -> [1]arpQuerierClient //input 1 for MAC address for arpQuerier
ClientPacketClassifier[2] -> ipCount_C -> StripEtherVLANHeader -> CheckIPHeader -> ipPacketClassifierClient
ClientPacketClassifier[3] -> DisCountARP_C -> Discard

//0 for icmp, 1 for tcp ,2 for others
ipPacketClassifierClient[0] -> icmpCount -> ICMPPingResponder -> ipPacketClient
ipPacketClassifierClient[1] -> [0]ipRewrite
ipPacketClassifierClient[2] -> DisCountIP_C -> Discard

//a packet from server(Port2)
fd2 -> InputCount_S -> ServerPacketClassifier

ServerPacketClassifier[0] -> arpReqCount1 ->arpRespondServer -> toServer;
ServerPacketClassifier[1] -> arpQueCount1 -> [1]arpQuerierServer;
ServerPacketClassifier[2] -> ipCount_S -> StripEtherVLANHeader -> CheckIPHeader -> ipPacketClassifierServer;
ServerPacketClassifier[3] -> DisCountARP_S -> Discard;

ipPacketClassifierServer[0] -> icmpCount1 -> ICMPPingResponder -> ipPacketServer;
ipPacketClassifierServer[1] -> [0]ipRewrite;
ipPacketClassifierServer[2] -> DisCountIP_S -> Discard;

// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit

DriverManager(wait , print > ./results/lb1.report "
    ==============lb1.report===============
    Input Packet Rate(pps) : $(add $(InputCount_C.rate) $(InputCount_S.rate))
    Output Packet Rate(pps) : $(add $(OutputCount_C.rate) $(OutputCount_S.rate))
    Total # of input packet : $(add $(InputCount_C.count) $(InputCount_S.count))
    Total # of output packet : $(add $(OutputCount_C.count) $(OutputCount_S.count))
    Total # of ARP requests : $(add $(arpReqCount.count) $(arpReqCount1.count))
    Total # of ARP responses : $(add $(arpQueCount.count) $(arpQueCount1.count))
    Total # of service packets : $(add $(ipCount_C.count) $(ipCount_S.count))
    Total # of ICMP packets : $(add $(icmpCount.count) $(icmpCount.count))
    Total # of dropped packets : $(add $(DisCountARP_C.count) $(DisCountIP_C.count) $(DisCountARP_S.count) $(DisCountIP_S.count))
    ======================================",
    stop);