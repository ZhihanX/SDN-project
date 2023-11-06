poxdir ?= /opt/pox/

topo:
	@echo "starting the topology! (i.e., running mininet)"
	sudo python topology/topology.py

app:
	@echo "starting the baseController!"
	cp applications/sdn/*.py /opt/pox/ext/
	python $(poxdir)/pox.py baseController

test:
	@echo "starting test scenarios!"
	@echo "starting controller"
	@make app >/dev/null 2>&1 &
	@sleep 2
	@echo "starting topology and tests"
	@sudo python topology/topology_test.py
	@echo "cleaning up controller"
	@sudo pkill click
	@pkill make

clean:
	@echo "project files removed from pox directory!"
	sudo mn -c
	rm -r /opt/pox/ext/*
	sudo killall python
	sudo pkill click
