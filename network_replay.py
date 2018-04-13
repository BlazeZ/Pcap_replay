import argparse
import os
import paramiko
import signal
import sys
import yaml
import subprocess
import time

NETWORK_MGR = None

class ReplayProcess:

    @staticmethod
    def client_config_to_args(cfg):
        args = [
            "cd", "pcap_replay", "&&",
            "./pcap_replay.py",
            "client",
            "--ip", cfg["server_ip"],
            "--port", str(cfg["port"]),
            "--pcap", "\"%s\"" % cfg["pcap"],
            "--num", str(cfg["num"]),
            "--control-ip", cfg["control_ip"],
            "--control-port", str(cfg["control_port"]),
            "--rate", str(cfg["rate"]),
            "--infinite" if cfg["infinite"] else "",
        ]
        return args

    @staticmethod
    def client_real_config_to_args(cfg):
        args = [
            "cd", "pcap_replay", "&&",
            "./pcap_replay.py",
            "client",
            "--ip", cfg["server_ip"],
            "--port", str(cfg["port"]),
            "--pcap", "\"%s\"" % cfg["pcap"],
            "--num", str(cfg["num"]),
            "--rate", str(cfg["rate"]),
            "--real",
            "--infinite" if cfg["infinite"] else "",
        ]
        return args


    @staticmethod
    def server_config_to_args(cfg):
        args = [
            "cd", "pcap_replay", "&&",
            "./pcap_replay.py",
            "server",
            "--store", cfg["store"],
            "--ip", cfg["ip"],
            "--port", str(cfg["port"]),
            "--control-ip", cfg["control_ip"],
            "--control-port", str(cfg["control_port"]),
            "--keep",
        ]
        return args

    def __init__(self, client, cfg, log_dir):
        self._client = client
        self._cfg_type = cfg["type"]
        self._name = cfg["name"]
        self._dispatchers = {
            "client"        : ReplayProcess.client_config_to_args,
            "client_real"   : ReplayProcess.client_real_config_to_args,
            "server"        : ReplayProcess.server_config_to_args,
        }
        proc_log_dir = os.path.join(log_dir, self._name)
        try:
            os.mkdir(proc_log_dir, 0777)
        except OSError:
            pass

        # Create the directory for this process instance
        start_time = int(time.time() * 1000)
        current_dir = os.path.join(proc_log_dir, str(start_time))

        try:
            os.mkdir(current_dir)
        except OSError:
            pass

        self._proc_stdout_file = open(os.path.join(current_dir, "stdout"), "w")
        self._proc_stderr_file = open(os.path.join(current_dir, "stderr"), "w")

        print "Starting process '%s' with log dir '%s'" % \
                (self.name(), current_dir)

        args = self._dispatchers[self._cfg_type](cfg)

        self._chan = self._client.get_transport().open_session()
        self._chan.exec_command(" ".join(args))


    def close(self):
        print "Closing process '%s'" % self.name()
        self._chan.close()
        self.flush(True)
        while not self._chan.exit_status_ready():
            time.sleep(.1)

    def flush(self, done=False):
        while self._chan.recv_ready():
            self._proc_stdout_file.write(self._chan.recv(1024))
            if not done:
                break

        while self._chan.recv_stderr_ready():
            self._proc_stderr_file.write(self._chan.recv_stderr(1024))
            if not done:
                break

        self._proc_stderr_file.flush()
        self._proc_stdout_file.flush()

    def name(self):
        return self._name

    def poll(self):
        return self._chan.exit_status_ready()

    def returncode(self):
        return self._chan.recv_exit_status()


class NetworkReplayMgr:

    def __init__(self, cfg):
        self._global_cfg = cfg["global"]
        self._node_cfgs = cfg["nodes"]
        self._procs = list()
        self._ssh_clients = dict()

    # Make sure this operation is atomic so that we don't kill a process that
    # is started after the kill operation
    def _kill(self, c):
        kill_chan = c.get_transport().open_session()
        kill_chan.exec_command("killall -9 pcap_replay.py")
        while not kill_chan.exit_status_ready():
            time.sleep(.1)

    def _close_clients(self):
        for n,c in self._ssh_clients.iteritems():
            print "Closing SSH session '%s'" % n
            # Kill any orphaned processes
            self._kill(c)
            c.close()

    def _make_connections(self):
        for cfg in self._node_cfgs:
            c = paramiko.SSHClient()
            c.load_system_host_keys()
            c.set_missing_host_key_policy(paramiko.WarningPolicy()) 
            c.connect(cfg["ssh_host"], 22, cfg["ssh_username"])

            # Kill any orphaned processes
            self._kill(c)

            self._ssh_clients[cfg["name"]] = c

    def _start_processes(self):
        for cfg in self._node_cfgs:
            p = ReplayProcess(self._ssh_clients[cfg["name"]],
                              cfg,
                              self._global_cfg["log_dir"])
            self._procs.append(p)
        self._running_procs = set(range(len(self._procs)))

    def loop(self):
        first = True
        while first or self._global_cfg["infinite"]:
            self.start()
            self.wait()
            first = False

        self._close_clients()

    def start(self):
        print "Logging output to directory: %s" % self._global_cfg["log_dir"]
        try:
            os.makedirs(self._global_cfg["log_dir"], 0777)
        except OSError:
            pass

        self._make_connections()
        self._start_processes()

    def wait(self):
        closed_ctr = 0
        # exit when all processes have closed
        while closed_ctr < len(self._procs):
            # flush output
            for p_ix in range(len(self._procs)):
                if p_ix in self._running_procs:
                    self._procs[p_ix].flush()

            # check for process exits
            for p_ix in range(len(self._procs)):
                if p_ix in self._running_procs:
                    p = self._procs[p_ix]
                    if p.poll():
                        print "Process '%s' exited with returncode '%d'" % \
                                    (p.name(), p.returncode())
                        p.close()
                        closed_ctr += 1
                        self._running_procs.remove(p_ix)
            # sleep to avoid burning the CPU
            time.sleep(.1)

        # clear the list of active proceseses
        self._procs = list()

    def close(self):
        for p_ix in range(len(self._procs)):
            if p_ix in self._running_procs:
                p = self._procs[p_ix]
                p.close()
        self._close_clients()

def handler(sig, frame):
    NETWORK_MGR.close()
    sys.exit(0)

def do_client(args):
    global NETWORK_MGR
    try:
        config_file = open(args.config, "r")
    except IOError:
        sys.stderr.write("Error: failed to open config file '%s'\n" % \
                    args.config)
        return 1

    yaml_config = yaml.load(config_file.read())

    NETWORK_MGR = NetworkReplayMgr(yaml_config)
    NETWORK_MGR.loop()


###
### main
###
def main():
    parser = argparse.ArgumentParser(prog = sys.argv[0])

    parser.add_argument("--config", dest = "config", type=str, required = True, help = "Config file for specifying network replay")

    args = parser.parse_args(sys.argv[1:])
    do_client(args)

    return 0

if __name__ == "__main__":
    try:
        signal.signal(signal.SIGINT, handler)
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)    


