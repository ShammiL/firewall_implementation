#!usr/bin/python3

import socket
import struct
import textwrap
import os

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t - '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    os.popen("sudo bash ./config.sh")
    table = os.popen("sudo iptables -L -n -v").read()

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 6:
                (src_port, dest_port, sequence, acknowledgement) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))

            elif proto == 17:
                src_port, dest_port, length = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
            print(read_iptables(table, src, target, proto, src_port, dest_port))


#unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return properly formatted MAC address(ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#return properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

#unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

    return src_port, dest_port, sequence, acknowledgement

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size


def read_iptables(table, source, dest, prot, s_port, d_port):
    lines = table.split('\n')
    for line in lines:
        words = line.strip().split()
        if  len(words) == 0:
            continue
        elif words[0] == 'Chain' or words[0] == 'pkts':
            continue
        elif len(words) == 9:
            d = {
                "target": words[2],
                "prot": words[3],
                "source": words[7],
                "destination": words[8],
                "port" : False
            }
        elif len(words) > 9:
            d = {
                "target": words[2],
                "prot": words[3],
                "source": words[7],
                "destination": words[8],
                "port" : words[10][3:]
            }
        if prot == d['prot'] or d['prot'] == 'all':
            if source == d['source'] or dest == d['destination'] or s_port == d['port'] or d_port == d['port']:
                if d['target'] == 'ACCEPT':
                    return "Accepted"
                else:
                    return "Rejected"
            else:
                return "Accepted"

main()

