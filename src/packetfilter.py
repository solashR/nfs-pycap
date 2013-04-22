#!/usr/bin/env python

import struct
import time

import pcap
import socket
import string
import sys

__author__ = "tigran"
__date__ = "$Jun 29, 2010 3:57:01 PM$"

protocols = {socket.IPPROTO_TCP:'tcp',
    socket.IPPROTO_UDP:'udp',
    socket.IPPROTO_ICMP:'icmp'}

hit = 0
message_types = {0:'CALL', 1:'REPLY'}

def decode_ip_packet(s):
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['tos'] = ord(s[1])
    d['total_len'] = struct.unpack('>H', s[2:4])[0]
    d['id'] = struct.unpack('>H', s[4:6])[0]
    d['flags'] = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset'] = struct.unpack('>H', s[6:8])[0] & 0x1f
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = struct.unpack('>H', s[10:12])[0]
    d['source_address'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20:4 * (d['header_len']-5)]
    else:
        d['options'] = None
    d['data'] = s[4 * d['header_len']:]
    return d

def decode_tcp_packet(s):
    d = {}
    d['source_port'] = (ord(s[0]) << 8) + ord(s[1])
    d['destination_port'] = (ord(s[2]) << 8) + ord(s[3])
    d['data_offset'] = (ord(s[12]) & 0xf0) >> 4
    d['flags'] = ord(s[13])
    if d['data_offset'] > 5:
        d['options'] = s[20:4 * (d['data_offset']-5)]
    else:
        d['options'] = None
    d['data'] = s[4 * d['data_offset']:]

    return d

def decode_udp_packet(s):
    d = {}
    d['source_port'] = (ord(s[0]) << 8) + ord(s[1])
    d['destination_port'] = (ord(s[2]) << 8) + ord(s[3])
    d['lengh'] = (ord(s[4]) << 8) + ord(s[5])
    d['checksum'] = (ord(s[6]) << 8) + ord(s[7])
    d['data'] = s[4 * d['lengh']:]

    return d


def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s))
    for i in xrange(0, len(bytes) / 16):
        print '        %s' % string.join(bytes[i * 16:(i + 1) * 16], ' ')
    print '        %s' % string.join(bytes[(i + 1) * 16:], ' ')


def print_packet(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14] == '\x08\x00':
        decoded = decode_ip_packet(data[14:])
        tcp = decode_tcp_packet(decoded['data'])
        print '\n%s.%f %s:%s > %s:%s' % (time.strftime('%H:%M',
                                         time.localtime(timestamp)),
                                         timestamp % 60,
                                         decoded['source_address'],
                                         tcp['source_port'],
                                         decoded['destination_address'],
                                         tcp['destination_port'])
        for key in ['version', 'header_len', 'tos', 'total_len', 'id',
            'flags', 'fragment_offset', 'ttl']:
            print '    %s: %d' % (key, decoded[key])

        try:
            print '    protocol: %s' % protocols[decoded['protocol']]
        except:
            print '    protocolraw: %s' % decoded['protocol']
        print '    header checksum: %d' % decoded['checksum']
        print '    data:'
        dumphex(decoded['data'])

class XdrStream:

    def __init__(self, data):
        self.data = data
        self.index = 0

    def decode_int32(self):
        i = struct.unpack_from('>I', self.data, self.index)[0]
        self.index += 4
        return i

    def decode_int64(self):
        return (self.decode_int32() << 32) + self.decode_int32()

    def decode_opaque(self):
        size = self.decode_int32()
        padding = (4 - (size & 3)) & 3;
        opaque = self.data[self.index:self.index + size]
        self.index += size + padding
        return opaque

    def bytes(self, len):
        data = self.data[self.index:self.index+len]
        self.index += len
        return data

    def decode_string(self):
        return self.decode_opaque()

    def has_more_data(self):
        return self.index < len(self.data)

    def remaining(self):
        return len(self.data) - self.index

class RpcMessage:
    def __init__(self):
        self.data = ''

    def add_data(self, data):
        self.data = self.data + data

    def get_xdr(self):
        return XdrStream(self.data)

def rpc_decode_auth(m):
    auth = {}
    auth['type'] = m.decode_int32()
    auth['body'] = m.decode_opaque()
    return auth

def rpc_decode_call(m):
    call = {}
    call['rpcvers'] = m.decode_int32()
    call['prog'] = m.decode_int32()
    call['vers'] = m.decode_int32()
    call['proc'] = m.decode_int32()

    return call

def nfs_v3_decode_read(m):
    fh = m.decode_opaque()
    offset = m.decode_int64()
    len = m.decode_int32()
    return fh, offset, len

def nfs_v3_decode_write(m):
    fh = m.decode_opaque()
    offset = m.decode_int64()
    len = m.decode_int32()
    how = m.decode_int32()
    data = m.bytes(len)
    return fh, offset, len

def nfs_v3_decode_create(m):
    fh = m.decode_opaque()
    path = m.decode_string()
    return fh, path

def dump_fh(fh):
    bytes = map(lambda x: '%.2x' % x, map(ord, fh))
    return string.join(bytes, '')

def rpcdecode(rpc_message):

    global hit
    rpc = {}
    rpc['xid'] = rpc_message.decode_int32()
    type = rpc_message.decode_int32()
    if type != 0 and type != 1:
        return
    rpc['type'] = message_types[type]

    if rpc['type'] == 'CALL':

        call = rpc_decode_call(rpc_message)
        if call['rpcvers'] != 2:
            return
        # cred
        rpc_decode_auth(rpc_message)
        # verf
        rpc_decode_auth(rpc_message)

        if call['prog'] == 100003 and call['vers'] == 3 and call['proc'] == 6:
            fh, offset, len = nfs_v3_decode_read(rpc_message)
            hit += 1
            print hit, dump_fh(fh), offset, len

        if call['prog'] == 100003 and call['vers'] == 3 and call['proc'] == 7:
            fh, offset, len = nfs_v3_decode_write(rpc_message)
            hit += 1
            print hit, dump_fh(fh), offset, len

        if call['prog'] == 100003 and call['vers'] == 3 and call['proc'] == 8:
            fh, path = nfs_v3_decode_create(rpc_message)
            hit += 1
            print hit, dump_fh(fh), path


class XdrPump:
    def __init__(self, pcap):
        self.pcap = pcap

    def next(self):
        while 1:
            packet = self.pcap.next()
            if packet is None:
                return None
            pktlen, data, timestamp = packet
            decoded = decode_ip_packet(data[14:])
            tcp = decode_tcp_packet(decoded['data'])
            if tcp['flags'] & 0x18 != 0 and tcp['destination_port'] == 2049 and len(tcp['data']) > 0:
                return XdrStream(tcp['data'])

class RpcStream:

    def __init__(self, xdr_pump):
        self.xdr_pump = xdr_pump
        self.xdr = None

    def __iter__(self):
        return self

    def next(self):
        rpc = RpcMessage()
        last_fragment = False
        while not last_fragment:
            x = self.next_xdr()
            if x is None:
                raise StopIteration
            last_fragment, data = x
            rpc.add_data(data)
        return rpc

    def next_xdr(self):
        if (self.xdr is None) or not self.xdr.has_more_data():
            self.xdr = self.xdr_pump.next()
        else:
            print 'multimessage packet'

        if self.xdr is None:
            return None

        header = self.xdr.decode_int32()
        len = header & 0x7fffffff
        last_fragment = (header & 0x80000000) != 0
        return last_fragment, self.xdr.bytes(len)

def packet_filter(pktlen, data, timestamp):
    if not data:
        return

    decoded = decode_ip_packet(data[14:])
    tcp = decode_tcp_packet(decoded['data'])
#    print "%x" % tcp['flags']
    if tcp['flags'] & 0x8 != 0:
        rpcdecode(tcp['data'])

if __name__ == "__main__":

    p = pcap.pcapObject()
    p.open_offline(sys.argv[1])
    p.setfilter('tcp and port 2049', 0, 0)

    rpc_stream = RpcStream(XdrPump(p))
    for rpc in rpc_stream:
        rpcdecode(rpc.get_xdr())
