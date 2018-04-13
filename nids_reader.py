# Deprecated: uses pynids to do stream reassembly. pynids / nids are pretty 
# terrible libraries so we've opted to use other solutions which may not
# provide stream re-assembly but are more stable.
import nids

import session_reader

class NidsSessionReader(session_reader.SessionReader):

    ONCE = True

    END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET) 
    def __init__(self, filename, num = 0):
        session_reader.SessionReader.__init__(self)
        self._filename = filename
        self._sessions = set()
        self._peers = None
        self._done = False
        self._session_ctr = 0
        self._session_num = num
        self._replaying = False

        # For some reason making this call to chksum_ctl() more than once
        # will cause a checksumming algorithm to run which fails and subsequently
        # doesn't pass to us the packets we need.
        if NidsSessionReader.ONCE:
            nids.chksum_ctl([('0.0.0.0/0', False)])
            NidsSessionReader.ONCE = False

        nids.param("filename", self._filename)
        nids.init()
        def NidsHandler(tcp):
            if tcp.nids_state == nids.NIDS_JUST_EST:
                # see if the address pairing has been observed before, if not
                # and we're not replaying already, then increase the session
                # counter because there's a new session. add the peers to the
                # set of known peer sessions. if the session counter is the
                # equal to the one provided by the caller, then start collection
                # for that session
                print "Session %d established" % self._session_ctr
                if not tcp.addr in self._sessions and not self._replaying:
                    self._peers = tcp.addr

                    if self._session_ctr == self._session_num:
                        print "Saw expected session, now replaying"
                        self._replaying = True
                        tcp.client.collect = 1
                        tcp.server.collect = 1
                self._sessions.add(tcp.addr)
                self._session_ctr += 1

            elif tcp.nids_state == nids.NIDS_DATA:
                print "Saw data for session"
                self._data = self._get_data(tcp)
                self._sender = self._get_sender(tcp)
            elif tcp.nids_state in NidsSessionReader.END_STATES:
                print "Session terminated"
                self._done = True

        nids.register_tcp(NidsHandler)

    def _get_data(self, tcp):
        if tcp.client.count_new > 0:
            sender = tcp.client
        else: 
            assert(tcp.server.count_new > 0)
            sender = tcp.server
        data = sender.data[0:sender.count_new]
        return data

    def _get_sender(self, tcp):
        if tcp.client.count_new > 0:
            return self._peers[1]
        else: 
            assert(tcp.server.count_new > 0)
            return self._peers[0]

    def _is_replaying(self):
        return self._replaying

    def count(self):
        while nids.next():
            continue
        return self._session_ctr

    def next(self):
        self._sender = None
        self._data = None
        while self._data == None and self._sender == None:
            if not nids.next():
                return None
        return self._sender, self._data

    def peers(self): 
        while not self._is_replaying():
            nids.next()
        return self._peers
            
