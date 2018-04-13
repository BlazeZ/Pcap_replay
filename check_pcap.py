import os
from subprocess import Popen, PIPE
import time
from notify import *
import sys
def get_pcap_list():
	pcap_dic = {}
	pcaps = os.listdir("pcap/dnp")
	return pcaps

def server(store):
	cmd = "./pcap_replay.py server --store "+store+" --port 20000 --control-port 50000 --keep"
	os.system(cmd)
def pipe():
	cmd = './pcap_replay.py client --pcap pcap/test --ip 10.16.1.4 --port 502  --real --num 1 --rate 1 --control-ip 172.16.1.4 --control-port 50000'
	process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
	out, err = process.communicate()
	email(err)
	print err

def main():
	pipe()

main()
