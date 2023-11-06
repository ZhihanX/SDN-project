// 2 variables to hold ports names
define($PORT1 ids-eth1, $PORT2 ids-eth2, $INSP ids-eth3)

// Define the negation of forbidden HTTP payloads
define($NOT_INJECTIONS !0/494E53455254 						// INSERT
					   !0/555044415445 						// UPDATE
					   !0/44454C455445 						// DELETE
					   !0/636174202F6574632F706173737764 	// cat /etc/passwd
					   !0/636174202F7661722F6C6F672F 		// cat /var/log/
)

// Script will run as soon as the router starts
Script(print "Click IDS on $PORT1 $PORT2")

// Define counter
InCnt_eth1,InCnt_eth2,OutCnt_eth1,OutCnt_eth2,OutCnt_insp :: AverageCounter;


//IPClassifier
elementclass DistinguishIP{
	input
	-> c::Classifier(12/0800,-);
	c[0] -> output     //IP packets
	c[1] -> [1]output  // others
}

elementclass IPChecksumFixer{ $print |
	input
	->SetIPChecksum
	-> class::IPClassifier(tcp, udp, -)

	class[0] -> Print(TCP, ACTIVE $print) -> SetTCPChecksum -> output
	class[1] -> Print(UDP, ACTIVE $print) -> SetUDPChecksum -> output
	class[2] -> Print(OTH, ACTIVE $print) -> output
}

// Group common elements in a single block. $port is a parameter used just to print
elementclass L2Forwarder {
	input
	->cnt::Counter
	->dip::DistinguishIP()
	->IPCnt::Counter
	->Strip(14)
	->SetIPChecksum
	->CheckIPHeader
	->IPChecksumFixer(0)
	->Unstrip(14)
	->output
	
	// Pass-through non-IP traffic
	dip[1] -> NonIPCnt::Counter-> output
}

elementclass UnstripFixer{ $name, $print |
	input
	-> Print($name, CONTENTS NONE, ACTIVE $print)
	-> IPChecksumFixer(0)
	-> Unstrip(14)
	-> output
}

elementclass DivertInjections{
	input
	// Set pointer to beginning of HTTP payload
	-> Search("\r\n\r\n")
	-> Print("HTTP REQUEST PAYLOAD", CONTENTS ASCII)
	// Classify traffic not containing injections, divert injections
	-> c::Classifier($NOT_INJECTIONS,-)
	-> NonInjCnt::Counter
	-> UnstripAnno()
	-> output

	// Injection detected, send to inspector
	c[1]-> InjCnt::Counter -> UnstripAnno() -> [1]output
}

// Set top-level IDS
elementclass IDS {
	input
	-> cnt::Counter
	-> dip::DistinguishIP()
	// Pass-through non-IP traffic
	dip[1] -> NonIPCnt::Counter -> output

	// Strip Ethernet header
	dip[0] -> IPCnt::Counter -> Strip(14)
	// Fix kernel bug, according to Canvas solution
	-> SetIPChecksum
	// Annotate IP header for IPClassifier
	-> CheckIPHeader(VERBOSE true)
	// Check if traffic is HTTP (tcp to port 80 and tcp push)
	-> httpc::IPClassifier(tcp dst port 80 and psh, -);
	// Not HTTP, so forward directly
	httpc[1] -> UnstripFixer("not HTTP", 0) -> output

	// Strip to beginning of HTTP
	httpc[0]-> HTTPCnt::Counter -> StripIPHeader
	-> StripTCPHeader
	// Classify POST/PUT/else
 	-> c::Classifier(0/504F5354, 0/505554, -);
	// Allow POST/PUT
	c[0] -> POSTCnt::Counter -> UnstripTCPHeader() -> UnstripIPHeader() -> UnstripFixer("POST", 0) -> output
	c[1] -> di::DivertInjections() -> PUTCnt::Counter -> UnstripTCPHeader() -> UnstripIPHeader() -> UnstripFixer("PUT", 0) -> output
	
	// Not POST or PUT, so to the inspector
	c[2] -> UnstripTCPHeader() -> UnstripIPHeader() -> UnstripFixer("wrong HTTP verb", 0) -> [1]output
	// Rejected code injections, so to the inspector
	di[1] -> UnstripTCPHeader() -> UnstripIPHeader() -> UnstripFixer("injection", 0) -> [1]output
}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Where to send packets
td1:: Queue ->ToDevice($PORT1, METHOD LINUX)
td2:: Queue ->ToDevice($PORT2, METHOD LINUX)
insp::Queue ->ToDevice($INSP, METHOD LINUX)

// Instantiate IDS and send forbidden traffic to the inspector
fd1 -> InCnt_eth1 -> ids::IDS() -> OutCnt_eth2 -> td2
ids[1] -> OutCnt_insp -> insp

// Instantiate 1 forwarder, towards Prz and PbZ
fd2 -> InCnt_eth2 -> fwd2::L2Forwarder()-> OutCnt_eth1 -> td1

// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
        print "IDS starting",
        pause,
		print > ./results/ids.report
		"=================== IDS report ===================
		Input Packet Rate (pps): $(add $(InCnt_eth1.rate) $(InCnt_eth2.rate))
		Output Packet Rate (pps): $(add $(OutCnt_eth1.rate) $(OutCnt_eth2.rate) $(OutCnt_insp.rate))

		Total # of IP packets: $(add $(fwd2/IPCnt.count) $(ids/IPCnt.count))
		Total # of non-IP packets: $(add $(fwd2/NonIPCnt.count) $(ids/NonIPCnt.count))

		Total # of HTTP packets: $(ids/HTTPCnt.count)
		Total # of POST requests: $(ids/POSTCnt.count)
		Total # of PUT requests: $(ids/PUTCnt.count)
		Total # of PUT requests with filtered injections: $(ids/di/InjCnt.count)
		Total # of PUT requests without filtered injections: $(ids/di/NonInjCnt.count)

		Total # of input packets: $(add $(InCnt_eth1.count) $(InCnt_eth2.count))
		Total # of forwarded packets: $(add $(OutCnt_eth1.count) $(OutCnt_eth2.count))
		Total # of diverted packets: $(OutCnt_insp.count)
		==================================================",
		stop
);
