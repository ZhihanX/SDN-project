// 2 variables to hold ports names eth1:DMZ eth2:Prz
define($PORT1 napt-eth1, $PORT2 napt-eth2)

// Script will run as soon as the router starts
Script(print "Click NAPT on $PORT1 $PORT2")

// Define counter
eth1InCounter,eth2InCounter,eth1OutCounter,eth2OutCounter :: AverageCounter;
arpReqCounter1,arpReqCounter2 :: Counter
arpReplyCounter1,arpReplyCounter2 :: Counter
tcpCounter1,tcpCounter2 :: Counter
icmpCounter1,icmpCounter2 :: Counter
dropCounter1,dropCounter2,dropCounter3,dropCounter4 :: Counter



//address AddressInfo

AddressInfo(
	Dmz	 100.0.0.1 10.0.0.0/24  42:1a:90:e8:40:92,
	Prz	 10.0.0.1 100.0.0.0/24   ab:cd:ef:12:34:56,
);

//Define from and to 
fromDmz::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fromPrz::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

toDmz  :: Queue -> ToDevice($PORT1, METHOD LINUX);
toPrz  :: Queue -> ToDevice($PORT2, METHOD LINUX);

// Packet classifier
fromDmzClassifier,fromPrzClassifier :: Classifier(
	12/0806 20/0001, //ARP request
	12/0806 20/0002, //ARP reply
	12/0800, 		 //IP
	- 				 //rest
); 			

//ARPQuerier. It has 2 input 0 and 1. The IP packet should pass through the input port 0. 
//After it get the ARP response from input port 1(include the Ethernet header), this IP packet will be sent to output port 0.
DmzARPQ :: ARPQuerier(Dmz)
PrzARPQ :: ARPQuerier(Prz)

//output after rewrite.The IP packet should pass through the ARPQuerier input port 0.
RewriteToDmz :: IPPrint("packet to Dmz") -> [0]DmzARPQ -> eth1OutCounter -> toDmz;
RewriteToPrz :: IPPrint("packet to Prz")-> [0]PrzARPQ -> eth2OutCounter  -> toPrz;

//ICMPPingRewriter has 6 parameters, here we just change the source address. We have 2 input from 2 directions.
//Here we just rewrite the source IP. Two input port will share the same table of mappings
icmpRewriter :: ICMPPingRewriter(pattern 100.0.0.1 - - - 0 1,pattern 10.0.0.1 - - - 1 0);
icmpRewriter[0] -> RewriteToDmz;
icmpRewriter[1] -> RewriteToPrz;

//IPRewriter(the same)
ipRewriter :: IPRewriter(pattern 100.0.0.1 - - - 0 1,pattern 10.0.0.1 - - - 1 0);
ipRewriter[0] -> RewriteToDmz;
ipRewriter[1] -> RewriteToPrz;


//Dmz IP classifier,we just make sure if it is an ICMP or tcp and drop the remaining. Then we pass them to ip and icmp rewriter
DmzIPClassifier :: IPClassifier(icmp type echo-reply or icmp type echo , tcp, -); //IP packet
	DmzIPClassifier[0] -> icmpCounter1 -> [1]icmpRewriter;
	DmzIPClassifier[1] -> tcpCounter1 -> [1]ipRewriter;
	DmzIPClassifier[2] -> dropCounter2 -> Discard;

//fromDmz arp classifier
fromDmz -> eth1InCounter -> fromDmzClassifier;
	// We need to send ARPResponder to 100.0.0.1(host IP) and 100.0.0.0/24 (a local subnet), see information about AddressInfo Dmz.
	fromDmzClassifier[0] -> arpReqCounter1-> ARPResponder(Dmz) -> toDmz //arp request
	//Here the arp reply is sent to ARPQuerier input port 1 in order to lead the final ip pactet.Otherwise the IP packet cannot find the mac address.
	fromDmzClassifier[1] -> arpReplyCounter1-> [1]DmzARPQ  //arp reply
	//We first StripEtherVLANHeader and shape the remaining packet to a IP packet and then sent it to a IPClassifier.
	fromDmzClassifier[2] -> Strip(14) -> Print("before") -> Print("after") -> CheckIPHeader -> IPPrint("packet from Dmz") -> DmzIPClassifier;
	fromDmzClassifier[3] -> dropCounter1 -> Discard;



//Prz IP classifier(the same)
PrzIPClassifier :: IPClassifier(icmp type echo-reply or icmp type echo , tcp, -); //IP packet
	PrzIPClassifier[0] -> icmpCounter2 -> [0]icmpRewriter;
	PrzIPClassifier[1] -> tcpCounter2 -> [0]ipRewriter;
	PrzIPClassifier[2] -> dropCounter4 -> Discard;

//fromPrz arp classifier(the same)
fromPrz -> eth2InCounter -> fromPrzClassifier;
	fromPrzClassifier[0] -> arpReqCounter2 -> ARPResponder(Prz) -> toPrz //arp request
	fromPrzClassifier[1] -> arpReplyCounter2 -> [1]PrzARPQ  //arp reply
	fromPrzClassifier[2] -> StripEtherVLANHeader -> Print("before") -> CheckIPHeader -> Print("after")-> IPPrint("packet from Prz") -> PrzIPClassifier;
	fromPrzClassifier[3] -> dropCounter3 -> Discard;

DriverManager(wait , print > ./results/napt.report  "
	=================== napt report ===================
	Input Packet Rate (pps): $(add $(eth1InCounter.rate) $(eth2InCounter.rate))
	Output Packet Rate (pps): $(add $(eth1OutCounter.rate) $(eth2OutCounter.rate))

	Total # of ARP request packets: $(add $(arpReqCounter1.count) $(arpReqCounter2.count))
	Total # of ARP reply packets: $(add $(arpReplyCounter1.count) $(arpReplyCounter2.count))

	Total # of TCP packets: $(add $(tcpCounter1.count) $(tcpCounter2.count))
	Total # of ICMP packets: $(add $(icmpCounter1.count) $(icmpCounter2.count))

	Total # of input packets: $(add $(eth1InCounter.count) $(eth2InCounter.count))
	Total # of output packets: $(add $(eth1OutCounter.count) $(eth2OutCounter.count))
	Total # of dropped packets: $(add $(dropCounter1.count) $(dropCounter2.count) $(dropCounter3.count) $(dropCounter4.count) )
	==================================================
" , stop);

