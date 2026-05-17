#!/usr/bin/env python3
import fcntl
import ipaddress
import os
import select
import signal
import socket
import struct
import sys
import time


SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX = 0x8933
ETH_P_IPV6 = 0x86DD
ICMPV6_RA = 134
ICMPV6_RS = 133
ALL_NODES = "ff02::1"
ALL_ROUTERS = "ff02::2"


running = True


def on_signal(_sig, _frame):
    global running
    running = False


signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)


def ifreq_value(ifname: str, req: int, size: int = 32) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        data = struct.pack("256s", ifname.encode())
        return fcntl.ioctl(s.fileno(), req, data)[:size]
    finally:
        s.close()


def interface_mac(ifname: str) -> bytes:
    return ifreq_value(ifname, SIOCGIFHWADDR)[18:24]


def interface_index(ifname: str) -> int:
    return struct.unpack("I", ifreq_value(ifname, SIOCGIFINDEX, 20)[16:20])[0]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def solicited_node_multicast(mac: bytes) -> bytes:
    return b"\x33\x33\x00\x00\x00\x01"


def ipv6_pseudo_header(src: bytes, dst: bytes, payload_len: int, next_header: int) -> bytes:
    return src + dst + struct.pack("!I3xB", payload_len, next_header)


def build_ra(src_mac: bytes, src_ip: bytes, prefix: ipaddress.IPv6Network, dns: ipaddress.IPv6Address) -> bytes:
    cur_hop_limit = 64
    flags = 0
    router_lifetime = 1800
    reachable_time = 0
    retrans_timer = 0

    ra_hdr = struct.pack(
        "!BBHBBHII",
        ICMPV6_RA,
        0,
        0,
        cur_hop_limit,
        flags,
        router_lifetime,
        reachable_time,
        retrans_timer,
    )

    slla = struct.pack("!BB6s", 1, 1, src_mac)
    mtu = struct.pack("!BBHI", 5, 1, 0, 1500)

    valid_lft = 86400
    preferred_lft = 14400
    prefix_info = struct.pack(
        "!BBBBIII16s",
        3,
        4,
        prefix.prefixlen,
        0xC0,
        valid_lft,
        preferred_lft,
        0,
        prefix.network_address.packed,
    )

    dns_bytes = dns.packed
    rdnss = struct.pack("!BBHI16s", 25, 3, 0, 1800, dns_bytes)

    payload = ra_hdr + slla + mtu + prefix_info + rdnss
    dst_ip = ipaddress.IPv6Address(ALL_NODES).packed
    pseudo = ipv6_pseudo_header(src_ip, dst_ip, len(payload), 58)
    csum = checksum(pseudo + payload)
    payload = payload[:2] + struct.pack("!H", csum) + payload[4:]
    return payload


def send_ra(sock: socket.socket, ifindex: int, src_mac: bytes, src_ip: bytes, prefix: ipaddress.IPv6Network, dns: ipaddress.IPv6Address) -> None:
    packet = build_ra(src_mac, src_ip, prefix, dns)
    sock.sendto(packet, (ALL_NODES, 0, 0, ifindex))


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: service-lan-ra.py <interface> <prefix> [dns]", file=sys.stderr)
        return 1

    ifname = sys.argv[1]
    prefix = ipaddress.IPv6Network(sys.argv[2], strict=False)
    dns = ipaddress.IPv6Address(sys.argv[3] if len(sys.argv) > 3 else "2606:4700:4700::1111")
    gateway = ipaddress.IPv6Address(os.getenv("SERVICE_LAN_IPV6_GATEWAY", str(prefix.network_address + 1)))

    ifindex = interface_index(ifname)
    src_mac = interface_mac(ifname)
    src_ip = gateway.packed

    send_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    send_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    send_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)

    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IPV6))
    recv_sock.bind((ifname, 0))
    recv_sock.setblocking(False)

    next_advert = 0.0
    while running:
        now = time.time()
        if now >= next_advert:
            send_ra(send_sock, ifindex, src_mac, src_ip, prefix, dns)
            next_advert = now + 10

        timeout = max(0.1, next_advert - now)
        ready, _, _ = select.select([recv_sock], [], [], timeout)
        if not ready:
            continue

        try:
            frame = recv_sock.recv(2048)
        except BlockingIOError:
            continue

        if len(frame) < 54:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        if ethertype != ETH_P_IPV6:
            continue
        version = frame[14] >> 4
        if version != 6:
            continue
        next_header = frame[20]
        hop_limit = frame[21]
        if next_header != 58 or hop_limit != 255:
            continue
        icmp_type = frame[54]
        if icmp_type == ICMPV6_RS:
            send_ra(send_sock, ifindex, src_mac, src_ip, prefix, dns)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
