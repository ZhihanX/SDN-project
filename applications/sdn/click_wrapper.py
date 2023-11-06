#!/usr/bin/python3

import os
import subprocess
import time
import signal
# TODO: Maybe you want to replace print with log.info?



"""
This is an helper wrapper to run Click on top of POX
This will be used in the NFV part of the project
"""


click_pids = []

def start_click(configuration, parameters, stdout="/tmp/click.out", stderr="/tmp/click.err"):

  # TODO: What do you want to do with the outputs?
  # Maybe you want them to a file? tee and > can be your friends!
  redirect = ""

  cmd = f"sudo click {configuration} {redirect} &"
  print(f"Launching click with command {cmd}")
  p = subprocess.Popen(cmd, shell=True)
  print(f"Click launched with PID {p.pid}")
  # Here we assume everything was ok
  # Maybe you want to check the return code, or if the actual process started?
  global click_pids
  click_pids.append(p.pid)
  return p


def handle_kill(sig, frame):
  # Instead of this, go through click_pids! We save them for a reason!
  print("Got kill signal. Notify all click processes")
  subprocess.check_output(
      "sudo killall -SIGTERM click || true", shell=True)
  exit(0)

def killall_click():
  subprocess.check_output("sudo killall -SIGTERM click || true", shell=True)

