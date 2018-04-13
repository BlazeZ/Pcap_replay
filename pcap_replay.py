#!/usr/bin/python

import atexit
import argparse
import glob
import json
import md5
import os
import random
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import datetime
from decimal import *
import dpkt_reader

debug = 0
begin_time = time.time()
DEFAULT_FLAGS = None
DEFAULT_IP = "127.0.0.1"
DEFAULT_DEV = "lo"
CONNECTION_COUNT = 0
time_check = []
DEFAULT_CONTROL_PORT=50000

CLIENT_SOCK = None
SERVER_SOCK = None

PENDING_PROC = None
child_pids = list()

IS_SERVER_BOUND = False
SESSION_TIMEOUT = 20
current_time = 0

def hexdump(src, length=16):
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
	lines = []
	for c in xrange(0, len(src), length):
		chars = src[c:c+length]
		hex = ' '.join(["%02x" % ord(x) for x in chars])
		printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
		lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
	return ''.join(lines)

def print_hexdump(data):
	if data == "" or data == None:
		print "<NONE>"
	else:
		print hexdump(data)

def null_mutator(data):
	return [data,]

def random_mutator(data, prob = .8):
	dl = list()

	cur_item = ""
	once = True
	for d in list(data):
		if once or random.random() < prob:
			cur_item += d
			once = False
		else:
			dl.append(cur_item)
			cur_item = d
			once = True

	if cur_item != "":
		dl.append(cur_item)
		cur_item = ""
		once = True
	return dl

def single_mutator(data):
	return list(data)


MUTATORS = {
	"null"   : null_mutator,
	"random" : random_mutator,
	"single" : single_mutator,
}

DEFAULT_MUTATOR = "random"

class PcapTCPSession(dpkt_reader.Session):

	def __init__(self):
		Session.__init__(self)
		self._client = None
		self._server = None
		self._play_idx = 0
		self._server_sem = threading.Semaphore(1)
		self._client_sem = threading.Semaphore(1)

	def client(self):
		return self._client

	def server(self):
		return self._server

	def wait_peer(self, session_type):
		if session_type == "Client":
			wait_client()
		elif session_type == "Server":
			wait_server()
		else:
			assert(0)

	def wait_server(self):
		self._server_sem.acquire()

	def wait_client(self):
		self._client_sem.acquire()

	def signal_server(self):
		self._server_sem.release()

	def signal_peer(self, session_type):
		if session_type == "Client":
			self.signal_client()
		elif session_type == "Server":
			self.signal_server()
		else:
			assert(0)

	def signal_client(self):
		self._client_sem.release()

	def reset(self):
		self._play_idx = 0

	def compare(self, oth):
		self.reset()
		oth.reset()

		play_data1 = self.play()
		play_data2 = oth.play()

		assert(play_data1 and play_data2)

		while play_data1 != None and play_data2 != None:
			if play_data1[0] != play_data2[0]:
				sys.stderr.write("Error: '%s' != '%s'\n" % \
					(play_data1[1].encode("hex"), play_data2[1].encode("hex")))
				return False

			if play_data1[1] != play_data2[1]:
				sys.stderr.write("Error: '%s' != '%s'\n" % \
					(play_data1[1].encode("hex"), play_data2[1].encode("hex")))
				return False

			self.increment()
			oth.increment()

			play_data1 = self.play()
			play_data2 = oth.play()

		if play_data1 or play_data2:
			sys.stderr.write("Session size mismatch\n")
			return False

		return True

def running_as_root():
	return os.geteuid() == 0

def mutate_session(session, mutator, flags):

	news = PcapTCPSession()

	while session.more():
		ept, data = session.play()
		mutl = mutator(data)

		for md in mutl:
			if ept == "Server":
				news.add_server_data(md)
			else:
				news.add_client_data(md)
		session.increment()

	session.reset()

	return news

def print_results(fail_flags, act_data, exp_data, idx):
	print "%s while waiting for data from play index: %d" % \
			(fail_flags,idx)
	if fail_flags == "CHECK_FAILED":
		print "Saw:"
		print_hexdump(act_data)
		print "Expected:"
		print_hexdump(exp_data)
	else:
		print "Saw:"
		print_hexdump(act_data)
		print "Expecting:"
		if act_data:
			print_hexdump(exp_data[len(act_data):])
		else:
			print_hexdump(None)

def server_thread_func(sock, session, rate, exit_on_error):

	#sock.settimeout(5)

	print "Waiting for protocol connection"
	try:
		conn_sock, peer = sock.accept()
	except socket.timeout:
		sys.stderr.write("Warning: timed out waiting for connection\n")
		return

	print "Connection received from peer: %s" % str(peer)
	do_session_server("Server", session, conn_sock, rate, exit_on_error)
	print "do session"

class Buffer:

	def __init__(self):
		self._data = ""

	def append(self, buf):
		self._data += buf

	def all(self):
		return self._data

	def get(self, size):
		if len(self._data) < size:
			return None
		popped = self._data[:size]
		self._data = self._data[size:]
		return popped

# In real mode, we can't do expect-like operations as we would in pcap mode
# because we assume the data is different from what was recorded in a pcap. So
# instead, we wait a hard-coded amount of time (500ms) to "know" when we are
# finished receiving
def recv_real_mode(conn_sock):
	start_time = time.time()
	data = ""
	fail_flags = None
	while time.time() - start_time < .5:
		try:
			conn_sock.settimeout(.1)
			data += conn_sock.recv(1024)
		except socket.timeout:
			break
		except socket.error as ex:
			fail_flags = "DISCONNECTED"
			break

	return fail_flags, data

def recv_pcap_mode(conn_sock, buf, play_data):
	fail_flags = None
	last_consumed_time = time.time()
	act_data = buf.get(len(play_data[1][1]))
	while not act_data and not fail_flags and time.time() - last_consumed_time < SESSION_TIMEOUT:
		try:
			data = conn_sock.recv(len(play_data[1][1]))
		except socket.error as ex:
			fail_flags = "DISCONNECTED"
			break

		buf.append(data)
		act_data = buf.get(len(play_data[1][1]))

	if not fail_flags:
		if time.time() - last_consumed_time > SESSION_TIMEOUT:
			fail_flags = "TIMED_OUT"
		elif act_data != play_data[1][1]:
			fail_flags = "CHECK_FAILED"

	return fail_flags, act_data


def do_session_server(session_type, session, conn_sock, rate, real = False, exit_on_error = False):
	fail_flags = None
	data = None

	buf = Buffer()

	while session.more() and not fail_flags:
		start_time = time.time()
		play_data = session.play()

		if not play_data:
			break

		if play_data[0] == session_type:
			assert(play_data[1] != "")
			assert(play_data[1][1] != "")
			
			print "--> %s Sending %d bytes for play index: %d" % \
							(session_type, len(play_data[1][1]), session.idx())
	
			# these sends must remain non blocking otherwise may get a race condition
			try:
				conn_sock.send(play_data[1][1])
			except socket.error:
				fail_flags = "DISCONNECTED"

			if not fail_flags and session.is_remote():
				session.increment()

		else:
			if real:
				fail_flags, data = recv_real_mode(conn_sock)
			else:
				fail_flags, data = recv_pcap_mode(conn_sock, buf, play_data)

			if not fail_flags:
				#print "--> %s Received %d bytes for play index: %d" % \
				#				(session_type, len(data), session.idx())
				session.increment()

		sys.stdout.flush()
		sys.stderr.flush()

	if fail_flags:
		print_results(fail_flags, data, play_data[1][1], session.idx())

		conn_sock.close()
		if exit_on_error:
			sys.exit(1)
		return False
	print "Closing connection with peer"
	conn_sock.close()
	return True


def do_session(session_type, session, conn_sock, rate, real = False, exit_on_error = False, realtime = 0):
	fail_flags = None
	data = None

	buf = Buffer()
	global current_time
	start_time = time.time()
	while session.more() and not fail_flags:

		c_time = time.time()
		play_data = session.play()

		if not play_data:
			break

		if realtime == "1":
			# current_time += Decimal(prec_int).quantize(Decimal(prec))
			assert(play_data[1] != "")
			assert(play_data[1][0] != "")
			assert(play_data[1][1] != "")
			# pkt_time = play_data[1][0]
			# print c_time, pkt_time
			delta = play_data[1][0]
			while c_time - start_time < delta:
				c_time = time.time()
				#print "moving forward in time: ", c_time - start_time, delta

			if play_data[0] == session_type:
				print "--> %s Sending %d bytes for play index: %d" % \
								(session_type, len(play_data[1][1]), session.idx())
				# these sends must remain non blocking otherwise may get a race condition

				try:
					conn_sock.send(play_data[1][1])
				except socket.error:
					fail_flags = "DISCONNECTED"

				if not fail_flags and session.is_remote():
					session.increment()

			else:
				if real:
					fail_flags, data = recv_real_mode(conn_sock)
				else:
					fail_flags, data = recv_pcap_mode(conn_sock, buf, play_data)
				if not fail_flags:
					if debug:
						print "--> %s Received %d bytes for play index: %d" % \
									(session_type, len(data), session.idx())
					session.increment()

		else:
			if play_data[0] == session_type:
					assert(play_data[1][1] != "")

					if rate:
						timeout = 1 / rate
						print "Sleeping for %2.4f seconds" % timeout
						time.sleep(timeout)
					print "--> %s Sending %d bytes for play index: %d" % \
									(session_type, len(play_data[1][1]), session.idx())
					# these sends must remain non blocking otherwise may get a race condition

					try:
						conn_sock.send(play_data[1][1])
						time_check.append((time.time() - start_time))
					except socket.error:
						fail_flags = "DISCONNECTED"

					if not fail_flags and session.is_remote():
						session.increment()
					#print "end"
			else:
				if real:
					fail_flags, data = recv_real_mode(conn_sock)
				else:
					fail_flags, data = recv_pcap_mode(conn_sock, buf, play_data)

				if not fail_flags:
					print "--> %s Received %d bytes for play index: %d" % \
									(session_type, len(data), session.idx())
					session.increment()
		#why are we flusing stout and stderr??
		sys.stdout.flush()
		sys.stderr.flush()

	if fail_flags:
		print_results(fail_flags, data, play_data[1][1], session.idx())
		conn_sock.close()
		if exit_on_error:
			sys.exit(1)
		return False

	print "Closing connection with peer"
	conn_sock.close()
	return True

def start_server_thread(sock, session, ip, port):
	t = threading.Thread(target = server_thread_func,
						 args = (sock, ip, port, session))
	t.start()
	return t

def join_server_thread(t):
	t.join()
	return True

def init_accept_socket(ip, port):
	global IS_SERVER_BOUND

	sock = init_socket()

	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	try:
		print "Binding to interface %s:%d" % (ip, port)
		sock.bind((ip, port))
	except socket.error:
		myhost = "hostname = " +os.uname()[1]
		sys.stderr.write("Error: failed to bind to %s:%d\n" % \
					(ip, port))
		return None

	sock.listen(1)
	IS_SERVER_BOUND = True
	return sock


def init_client_socket(bind_ip):
	s = init_socket()
	s.settimeout(60)

	if bind_ip:
		for i in range(10):
			bind_port = random.randint(1024, 65535)
			try:
				s.bind((bind_ip, bind_port))
				print 'blind control'
			except socket.error:
				print "Failed to bind to address: %s:%d" % \
						(bind_ip, bind_port)
				continue
			break
	return s

def init_socket():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
	s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	return s

def do_client_session(args, session):
	global CONNECTION_COUNT
	client_sock = init_client_socket(args.bind_ip)
	print "Connection %d, to %s:%d" % (CONNECTION_COUNT, args.ip_addr, args.port)
	CONNECTION_COUNT+=1
	try:
		client_sock.connect((args.ip_addr, args.port))
	except socket.error:
		sys.stderr.write("Error: failed to connect to %s:%d\n" % \
				(args.ip_addr, args.port))
		return False

	result = do_session("Client", session, client_sock, args.rate, args.real, args.exit_on_error,args.realtime)
	return result

def play_session(session, ip, port):
	global IS_SERVER_BOUND
	server_sock = init_accept_socket()
	client_sock = init_client_socket(None)
	if not server_sock or not client_sock:
		sys.stderr.write("Error: failed to initialize socket\n")
		return False

	sthread = start_server_thread(server_sock, session, ip, port)

	# Wait for the server to start
	#time.sleep(.5)
	if not IS_SERVER_BOUND:
		return False

	client_session(session, ip, port)
	join_server_thread(sthread)

	return True

def verify_recording(pcap_path, session):
	reader = dpkt_reader.DpktSessionReader(pcap_path)

	input_session = PcapTCPSession(reader)
	if not input_session:
		sys.stderr.write("Error: failed to load input streams\n")
		return False

	if not input_session.load():
		return None

	return session.compare(input_session)

def start_recording(port, path):
	global PENDING_PROC
	filt = "tcp and port %d" % port
	cmd = "tcpdump --immediate-mode -w %s -i %s %s" % (path, DEFAULT_DEV, filt)
	PENDING_PROC = subprocess.Popen(args = cmd.split(),
			stdout = subprocess.PIPE, stderr = subprocess.PIPE, stdin = subprocess.PIPE)

def stop_recording():
	global PENDING_PROC

	# the child should never terminate prematurely
	assert(PENDING_PROC.poll() == None)
	PENDING_PROC.send_signal(signal.SIGINT)
	PENDING_PROC.communicate()
	assert(PENDING_PROC != None)
	PENDING_PROC = None

def do_rounds(num_rounds, session, output_dir, flags, do_verify, mutator, ip, port):
	for i in range(num_rounds):
		new_session = mutate_session(session, mutator, flags)
		if not new_session:
			return False

		pcap_path = os.path.join(output_dir, "%d.pcap" % i)
		start_recording(port, pcap_path)
		if not play_session(new_session, ip, port):
			return False

		stop_recording()

		if do_verify:
			sys.stdout.write("Verifying the recording\n")
			if not verify_recording(pcap_path, new_session):
				sys.stderr.write("session verification failed\n")
				return False
			sys.stdout.write("\tSuccess!\n")
		sys.stdout.write("Successfully wrote pcap to %s\n" % pcap_path)
	return True

def lookup_mutator(mutator_name):
	if not mutator_name in MUTATORS:
		return None
	return MUTATORS[mutator_name]

def make_output_dir(dirname):
	if not os.path.exists(dirname):
		os.mkdir(dirname)

def do_fuzz(args):
	if not running_as_root():
		sys.stderr.write("Error: must run as root\n")
		return 1

	make_output_dir(args.output_dir)

	reader = dpkt_reader.DpktSessionReader(args.pcap)
	input_session = PcapTCPSession(reader)

	if not input_session.load():
		sys.stderr.write("Error: failed to load input streams\n")
		return 1

	mutator = lookup_mutator(args.mutator_name)
	if not mutator:
		sys.stderr.write("Error: failed to find mutator '%s'\n" % args.mutator_name)
		return 1

	server_port = input_session.server()[1]
	do_rounds(args.num,
			  input_session,
			  args.output_dir,
			  args.flags,
			  args.verify,
			  mutator,
			  DEFAULT_IP,
			  server_port)

def do_compare(args):

	# These accesses must be done in serial because the handler is global
	left = dpkt_reader.DpktSessionReader(args.left)
	lefts = PcapTCPSession(left)
	if not lefts.load():
		return False

	right = dpkt_reader.DpktSessionReader(args.right)
	rights = PcapTCPSession(right)
	if not rights.load():
		return False

	if lefts.compare(rights):
		print "Pcaps are equivalent"
	else:
		print "Pcaps are different"

def do_server_session(sock, pcap, session_num, rate, exit_on_error,reader):
	
	server_thread_func(sock, reader.get_session(session_num), rate, exit_on_error)
	return True

def sock_send(s, buf):
	try:
		s.send(buf)
	except socket.error:
		return False
	return True

def recv_control_msg(conn_sock):
	
	try:
		data = conn_sock.recv(4)
	except socket.error:
		print socket.error
		sys.stderr.write("Error: failed to receive control message\n")
		return None

	if len(data) != 4:
		sys.stderr.write("Error: failed to receive control message\n")
		return None
	size, = struct.unpack("<I", data)

	try:
		json_data = conn_sock.recv(size)
	except socket.error:
		sys.stderr.write("Error: failed to receive control message\n")
		return None

	msg = json.loads(json_data)
	print json_data
	return msg

def send_control_msg(conn_sock, msg):
	buf = json.dumps(msg)
	sbuf = struct.pack("<I", len(buf))
	if not sock_send(conn_sock, sbuf):
		return False
	if not sock_send(conn_sock, buf):
		return False
	return True

def send_response_msg(conn_sock, code):
	msg = dict()
	msg["result"] = code
	send_control_msg(conn_sock, msg)
	return True

def send_ok_msg(conn_sock):
	return send_response_msg(conn_sock, "ok")

def compute_md5_hash(filename):
	m = md5.new()
	try:
		data = open(filename, "rb").read()
	except IOError:
		sys.stdout.write("Error: failed to open file '%s'\n" % filename)
		return None
	m.update(data)
	return m.hexdigest()

def lookup_file(cfg, hashval):
	assert("store" in cfg)
	ext = "*.pcap"

	print "Searching '%s' for files with extension '%s'" % (cfg["store"], ext)
	files = glob.glob(os.path.join(cfg["store"], ext))
	for filepath in files:
		hashval_file = compute_md5_hash(filepath)
		if hashval_file == None:
			print "Warning: failed to calculate hash of file '%s', continuing" % filepath
			continue

		if hashval_file == hashval:
			return filepath

	if len(files) == 0:
		sys.stderr.write("Error: no file matching ext found\n")
		return None

	return None

def wait_for_client_control(cfg, control_sock):
	try:
		conn_sock, peer = control_sock.accept()
	except socket.error as ex:
		print "Warning: socket error (possibly SIGCHLD) while waiting for control event"
		return None

	print "Receiving control connection from peer '%s'" % str(peer)

	msg = recv_control_msg(conn_sock)
	if not msg:
		print "Warning: error while waiting for control message"
		return None

	filepath = lookup_file(cfg, msg["hash"])
	if not filepath:
		print "Warning: file with hash %s not found" % msg["hash"]
		if not send_response_msg(conn_sock, "file not found"):
			print "Warning: failed while sending response message"
			return None
		return None

	print "Found pcap '%s' with hash '%s'" % (filepath, msg["hash"])


	if not send_ok_msg(conn_sock):
		print "Error: failed to send OK response"
		return None

	assert("session_idx" in msg)
	conn_sock.close()
	print 'close'

	return filepath, msg["session_idx"], msg["rate"],


def init_control_channel(server_control_ip, server_control_port, pcap, session_num, rate):
	hashval_file = compute_md5_hash(pcap)
	if not hashval_file:
		sys.stderr.write("Error: failed to hash file '%s'\n" % pcap)
		return False
	
	sock = init_client_socket(None)

	try:
		print 'try to connect to control'
		sock.connect((server_control_ip, server_control_port))
	except socket.error:
		sys.stderr.write("Error: failed to connect to control channel '%s:%d\n" % \
				(server_control_ip, server_control_port))
		return False

	out_msg = {
			"hash" : hashval_file,
			"session_idx" : session_num,
			"rate" : rate,
	}
	print 'connected'
	
	if not send_control_msg(sock, out_msg):
		sys.stderr.write("Warning: failed to send control message")
		return False

	in_msg = recv_control_msg(sock)
	if not in_msg:
		sys.stderr.write("Error: failed to receive response from server\n")
		return False

	if in_msg["result"] != "ok":
		sys.stderr.write("Error: received '%s' error from server\n" % in_msg["result"])
		return False

	sock.close()

	return True

def load_config(args):
	cfg = dict()
	cfg["store"] = args.store
	return cfg

def send_ok_after_recv_pcap(control_sock):
	print 'in send ok'
	try:
		conn_sock, peer = control_sock.accept()
	except socket.error as ex:
		print "Warning: socket error (possibly SIGCHLD) while waiting for control event"
		return None

	
	if not send_ok_msg(conn_sock):
		print "Error: failed to send OK response"
		return None

	print 'sented ok msg'

def do_server(args):
	data_sock = init_accept_socket(args.ip_addr, args.port)
	if not data_sock:

		sys.stderr.write("Error: failed to initialize data socket\n")
		sys.exit(1)

	control_sock = init_accept_socket(args.control_ip, args.control_port)
	if not data_sock:
		sys.stderr.write("Error: failed to initialize control socket\n")
		sys.exit(1)

	cfg = load_config(args)

	first = True
	
	while first or args.keep_going:
		first = False
		result = wait_for_client_control(cfg, control_sock)
		if result == None:
			print "Warning: unexpected control event, continuing"
			continue

		pcap_filename, session_num, rate = result
		reader = dpkt_reader.DpktSessionReader(pcap_filename)
		finish = reader.load()
		global child_pids
		if finish:
			print 'finish loading pcap'
			conn_sock, peer = control_sock.accept()
			send_ok_msg(conn_sock)

		
		#pid = os.fork()
		pid =0
		# child
		if pid == 0:
			print do_server_session(data_sock, pcap_filename, session_num, rate, args.exit_on_error,reader)
		else:
			# parent
			print "Forked child process with pid %d" % pid
			child_pids.append(12)
			print child_pids

	for cp in child_pids:
		print "Waiting for child process with pid %d" % cp
		os.waitpid(cp, 0)
	print "asdsd"
	control_sock.close()
	return True

def do_client(args):

	if not args.real and not args.server_control_ip:
		sys.stderr.write("Error: control ip not specified\n")
		return False

	pcapcur = args.pcap
	reader = dpkt_reader.DpktSessionReader(pcapcur)
	global current_time

	reader.load()
	if args.session_num == "*":
		num_sessions = reader.count()
		session_cur_num = 0
	else:
		session_cur_num = int(args.session_num)
		if session_cur_num < reader.count():
			num_sessions = session_cur_num + 1
		else:
			sys.stderr.write("Error: session number '%d' exceeds maximum for pcap '%d'\n" % \
					(session_cur_num, reader.count()))
			return False


	while 1:

		for session_cur in range(session_cur_num, num_sessions):

			if not args.real:
				print "Initializing control channel"
				while not init_control_channel(args.server_control_ip,
											args.server_control_port,
											pcapcur,
											session_cur,
											args.rate):
					sys.stderr.write("Error: unable to initiate control channel\n")
					if not args.infinite:
						print "infinite"
						return False
					#time.sleep(.5)
			else:
				print "In 'real' mode. assuming server is an actual, not pcap-simulated host"

			'getting second ok msg'
			sock = init_client_socket(None)

			sock.connect((args.server_control_ip, args.server_control_port))
			hashval_file = compute_md5_hash(pcapcur)
			out_msg = {
			"hash" : hashval_file,
			"session_idx" : session_cur,
			"rate" : args.rate,
			}
			send_control_msg(sock, out_msg)
			in_msg = recv_control_msg(sock)
			print " finsh load on server"
			
			print "Using pcap %s with session number %d" % (pcapcur, session_cur)
			s = reader.get_session(session_cur)

			if not do_client_session(args, s):
				if not args.infinite:
					return False
			#time.sleep(.5)
			s.reset()


		if not args.infinite:
			print " break"
			break
	return True

###
### main
###
def main():
	parser = argparse.ArgumentParser(prog = sys.argv[0])
	subparsers = parser.add_subparsers()

	# compare
	parser_compare = subparsers.add_parser("compare")
	parser_compare.add_argument("--left", dest = "left", type = str, default = "", required = True, help = "file to compare")
	parser_compare.add_argument("--right", dest = "right", type = str, default = "", required = True, help = "file to compare")
	parser_compare.set_defaults(func = do_compare)

	# fuzz
	parser_fuzz = subparsers.add_parser("fuzz")

	parser_fuzz.add_argument("--pcap", dest = "pcap", type=str, default = "", required = True, help = "pcap file to ingest")
	parser_fuzz.add_argument("--output-dir", dest = "output_dir", type=str, default = "", required = True, help = "directory to output mutated TCP stream PCAPs")
	parser_fuzz.add_argument("--num", dest = "num", type = int, default = 1, required = False,
		help = "the number of mutation rounds")
	parser_fuzz.add_argument("--flags", dest = "flags", type = str, default = DEFAULT_FLAGS, required = False,
		help = "the number of mutation rounds")
	parser_fuzz.add_argument("--mutator", dest = "mutator_name", type = str, default = DEFAULT_MUTATOR, required = False,
		help = "the name of the mutator to use, one of: %s" % list(MUTATORS.iterkeys()))
	parser_fuzz.add_argument("--verify", dest = "verify", action = "store_true", default = False, required = False,
		help = "whether or not to verify each generating pcap vs. the expected mutation")
	parser_fuzz.set_defaults(func = do_fuzz)

	# client
	parser_client = subparsers.add_parser("client")
	parser_client.add_argument("--pcap", dest = "pcap", type=str, default = "", required = True, help = "glob expression of pcap files to ingest")
	parser_client.add_argument("--ip", dest = "ip_addr", type=str, default = "", required = True, help = "The IP to which we should connect")
	parser_client.add_argument("--control-ip", dest = "server_control_ip", type=str, default = None, required = False, help = "The Control IP to which we should connect")
	parser_client.add_argument("--control-port", dest = "server_control_port", type=int, default = DEFAULT_CONTROL_PORT, required = False, help = "The Control port to which we should connect")
	parser_client.add_argument("--port", dest = "port", type=int, default = "", required = True, help = "Port")
	parser_client.add_argument("--num", dest = "session_num", type=str, default = "*", required = False, help = "Session number to replay")
	parser_client.add_argument("--rate", dest = "rate", type=float, default = 0, required = False, help = "Rate of exchange (in msgs / second)")
	parser_client.add_argument("--infinite", dest = "infinite", default = False, action = "store_true", required = False, help = "Loop infinitely using pcap")
	parser_client.add_argument("--real", dest = "real", default = False, action = "store_true", required = False, help = "Communicate with a real host")
	parser_client.add_argument("--bind-ip", dest = "bind_ip", default = None, required = False, help = "Specify an IP for the client to bind (optional)")
	parser_client.add_argument("--realtime", dest = "realtime", default = 0, required = False, help = "real time pcap (optional)")
	parser_client.add_argument("--exit-on-error", dest = "exit_on_error", default = False, required = False, action="store_true", help = "Exit if an error occurs")
	parser_client.set_defaults(func = do_client)

	# server
	parser_server = subparsers.add_parser("server")
	parser_server.add_argument("--store", dest = "store", type=str, default = "", required = True, help = "Directory of .pcap files")
	parser_server.add_argument("--ip", dest = "ip_addr", type=str, default = "0.0.0.0", required = False, help = "The protocol IP on which to bind")
	parser_server.add_argument("--port", dest = "port", type=int, default = "", required = True, help = "The protocol Port on which to bind")
	parser_server.add_argument("--control-ip", dest = "control_ip", type=str, default = "0.0.0.0", required = False, help = "The control IP on which to bind")
	parser_server.add_argument("--control-port", dest = "control_port", type=int, default = DEFAULT_CONTROL_PORT, required = False, help = "The Control port on which to bind")
	parser_server.add_argument("--keep", dest = "keep_going", default = 0, required = False, action="store_true", help = "Keep going or quit after one session")
	parser_server.add_argument("--exit-on-error", dest = "exit_on_error", default = False, required = False, action="store_true", help = "Exit if an error occurs")
	parser_server.set_defaults(func = do_server)

	args = parser.parse_args(sys.argv[1:])
	if not args.func(args):
		return 1

	return 0

def handler(sig, frame):
	print "Received SIGCHLD"

if __name__ == "__main__":
	try:
		signal.signal(signal.SIGCHLD, handler)
		main()
		print "My program took", (time.time() - begin_time)/60 , " min to run ",(time.time() - begin_time) ,"sec"
	except KeyboardInterrupt:
		sys.exit(1)

	except Exception as e:
		print e