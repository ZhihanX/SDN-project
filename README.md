## Task list

-  [x] Topology
-  [x] L2 Learning switches
- [x] Implement Firewalls
  - [x] Parse Packets (e.g. ARP, UDP, and TCP)
  - [x] Check the firewall rules
  - [x] Install appropriate OpenFlow rules
- [x] Control Interface
  - [x] Client to switch-port mapping
  - [x] Global MAC mapping
  - [x] Rule flushing
- [x] Testing (Follow rules in assignment description)
  - [x] Ping
  - [ ] iperf
  - [x] http servers
- [x] Makefile
  - [x] Keep up to date
  - [x] topo
  - [x] app
  - [x] test
  - [x] clean
- [ ] Upload project
  - [ ] remove git files
  - [ ] zip folder
  - [ ] Upload to Canvas

## How to run the project

**make topo:**

Starts mininet topology


**make app:**

Starts the controller.
The default pox directory is set to '/opt/pox/'.
However one should be able to overwrite it using make input.

Example:
`$ make poxdir=/pox/base/directory/ app`

**make test:**

Restarts topology, and the sdn controller. Then it runs provided test scenarios.

**make clean:**

Removes all junks added to different directories to run the application.

