#!/usr/bin/python3

from flask import Flask, request, jsonify
import threading
from pprint import pprint, pformat
from time import sleep
from datetime import datetime
import json
import struct
from pox.forwarding.l2_learning import LearningSwitch

app = Flask(__name__)


def htmlify(content, req, replace=True):
    # Feel free to update this function in case you want have a different HTML style
    s = "<html><body>"
    s += "<a href='/'> Go Back</a> \n<br>\n"
    if (replace):
        s += content.replace("\n", "\n<br>\n")
    else:
        s += content
    s += "</body></html>"
    return s


# When visiting /macs_map we want to see a map of the MAC addresses and to which switch port they have been seen incoming
# Hint: the events are sequential
#       So you can keep a list of the "first seen at" at the controller
#       And update that from each device when new packets come (and the source MAC is unknown)

@app.route('/macs_map')
def macs_map():
    res = ""
    res += f"Global MAC table\n"

    for key, value in sorted(controller.firstSeenAt.items()):

        res += f"{key} : {value[0]} @ {value[1]}\n"

    return htmlify(res, request, True)


# When visiting /macs we should have a list of MAC addresses and to which port they have been seen
# They should be dividided by device
# The difference with the above is that here we want to see **all** mac addresses incoming to any port
# You should retrieve these information from the Python code of the L2 switches
@app.route('/macs')
def macs():
    res = ""

    for key, value in sorted(controller.devices.items()):

        res += f"MAC table of {value.name}\n"
        for ether, port in value.macToPort.items():
            res += f"* Port {port} - {ether}\n"
        res += "\n"

    return htmlify(res, request, True)


# Here we call the controller's function that flushes rules.
@app.route('/flush')
def flush():
    controller.flush()
    res = "Flushed!"
    return htmlify(res, request, True)


@app.route('/')
def index():
    # Feel free to change the main page with a design you like!
    s = ""
    s += "<body><html>"
    s += "Welcome to IK2220 OpenFlow Controller!<br>\n"
    s += "<a href='macs'> MAC table status</a><br></n>"
    s += "<a href='macs_map'> Global MAC map</a><br></n>"
    s += "<a href='flush'> Flush rules from all switches. Be careful! </a><br></n>"
    return s


def webserver(contr):
    global controller

    if contr is not None:
        controller = contr
    else:
        print("Controller is None!")

    # This starts a web server on a background thread on port 8080
    # All decorated methos with @app.route will be added as routes of the application
    threading.Thread(target=lambda:
                     app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)).start()
