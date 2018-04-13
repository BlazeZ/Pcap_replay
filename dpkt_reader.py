import dpkt
import session_reader

class Session:

    def __init__(self, peers):
        self._server_data_list = list()
        self._client_data_list = list()
        self._client_addr = peers[0]
        self._server_addr = peers[1]
        self._client_seq = None
        self._server_seq = None
        self._play_idx = 0

    def is_remote(self):
        return True

    def add_data(self, peer, data, seq, timestamp):

        if peer == self._client_addr:
            #print "Client, seq: %d" % seq
            if self._client_seq == None:
                self._client_seq = seq + len(data)
            else:
                assert seq == self._client_seq
                self._client_seq += len(data)

            self._client_data_list.append((timestamp, data))
            self._server_data_list.append(None)
        else:
            #print "Server, seq: %d" % seq
            if self._server_seq == None:
                self._server_seq = seq + len(data)
            else:
                assert seq == self._server_seq, "%d %d" % (seq, self._server_seq)
                self._server_seq += len(data)

            self._server_data_list.append((timestamp, data))
            self._client_data_list.append(None)

    def load(self):
        result = None
        while not self._session_reader.is_connected():
            result = self._session_reader.next()

        print "Getting peers for session"
        peers = self._session_reader.peers()
        if not peers:
            sys.stderr.write("Failed to identify peers\n")
            return False

        self._client, self._server = peers

        while not self._session_reader.is_terminated():
            result = self._session_reader.next()
            if result == None:
                continue
            sender, pkt = result
            self.add_pkt(sender, pkt)
        return True

    def idx(self):
        return self._play_idx

    def increment(self):
        self._play_idx += 1

    def play(self):
        play_data = None

        assert(len(self._server_data_list) == len(self._client_data_list))

        # we are done if the play index exceeds the session information
        if(self._play_idx >= len(self._server_data_list)):
            return None

        # one of these must be none so we can retain the data ordering
        # between client and server if we want to
        assert(self._server_data_list[self._play_idx] == None or
                self._client_data_list[self._play_idx] == None)

        if self._server_data_list[self._play_idx]  == None:
            play_data = "Client", self._client_data_list[self._play_idx]
        else:
            play_data = "Server", self._server_data_list[self._play_idx]

        return play_data

    def more(self):
        assert(len(self._server_data_list) == len(self._client_data_list))
        return self._play_idx < len(self._server_data_list)

    def reset(self):
        self._play_idx = 0

class DpktSessionReader(session_reader.SessionReader):

    def __init__(self, filename):
        session_reader.SessionReader.__init__(self)

        self._filename = filename

        print "Opening packet capture: %s" % self._filename
        self._pcap = list(dpkt.pcap.Reader(open(self._filename, "rb")))
        self._num_sessions = 0
        self._conn_map = dict()
        self._session_map = dict()

    def _identify_peers(self, ip_pkt):
        tcp_pkt = ip_pkt.data
        return ((ip_pkt.src, tcp_pkt.sport), (ip_pkt.dst, tcp_pkt.dport))

    def _is_flow_from_client(self, ip_pkt):
        src_peer, dst_peer = self._identify_peers(ip_pkt)
        if self._peers[0] == src_peer and self._peers[1] == dst_peer:
            return True
        return False

    def _is_flow_from_server(self, ip_pkt):
        src_peer, dst_peer = self._identify_peers(ip_pkt)
        if self._peers[0] == dst_peer and self._peers[1] == src_peer:
            return True
        return False

    def _is_connect(self, tcp_pkt):
        return tcp_pkt.flags & dpkt.tcp.TH_SYN and not tcp_pkt.flags & dpkt.tcp.TH_ACK

    def _is_terminate(self, tcp_pkt):
        TERMINATE_MASK = dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN
        return tcp_pkt.flags & TERMINATE_MASK

    def count(self):
        return self._num_sessions

    def get_session(self, idx):
        return self._conn_map[self._session_map[idx]]

    def load(self):
        tcp_pkt = None
        start_time = None
        for idx in range(len(self._pcap)):
            ts, buf = self._pcap[idx]
            if start_time is None:
                start_time= ts

            ip_pkt = dpkt.ethernet.Ethernet(buf).data
            if not type(ip_pkt) == dpkt.ip.IP:
                continue
            if type(ip_pkt.data) == dpkt.tcp.TCP:
                tcp_pkt = ip_pkt.data

                peers = self._identify_peers(ip_pkt)
                if not peers in self._conn_map and not (peers[1], peers[0]) in self._conn_map:
                    assert self._is_connect(tcp_pkt)
                    self._conn_map[peers] = Session(peers)
                    self._session_map[self._num_sessions] = peers
                    self._num_sessions+=1
                else:
                    if not peers in self._conn_map:
                        act_peers = (peers[1], peers[0])
                    else:
                        act_peers = peers
                    if len(tcp_pkt.data) > 0:
                        delta = ts - start_time
                        self._conn_map[act_peers].add_data(peers[0], tcp_pkt.data, tcp_pkt.seq, delta)

        return True
