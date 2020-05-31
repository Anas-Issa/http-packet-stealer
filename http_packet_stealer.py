import socket
import struct


class IpPacket(object):
    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_address(raw_ip_address: bytes) -> str: return ".".join(map(str, raw_ip_address))


def parsing_tcp_packet(ip_packet_payload: bytes) -> TcpPacket:
    source_port = int.from_bytes(ip_packet_payload[0:2], byteorder='big')
    destination_port = int.from_bytes(ip_packet_payload[2:4], byteorder='big')
    data_offset = int.from_bytes(ip_packet_payload[12:13], byteorder='big') >> 4
    payload_start = 4 * data_offset
    payload = ip_packet_payload[payload_start:]
    try:
        payload.decode('utf-8')
        return TcpPacket(source_port, destination_port, data_offset, payload)
    except UnicodeError:
        return TcpPacket(source_port, destination_port, data_offset, b'None')


def parsing_ip_packet(ip_packet: bytes) -> IpPacket:
    ihl = ip_packet[0] & 15
    protocol = ip_packet[9]
    source_address, destination_address = struct.unpack("! 4s 4s", ip_packet[12:20])
    payload_start = 4 * ihl
    payload = ip_packet[payload_start:]
    return IpPacket(protocol, ihl, parse_raw_ip_address(source_address), parse_raw_ip_address(destination_address),
                    payload)


def display(ip_object: IpPacket, tcp_object: TcpPacket):
    if tcp_object.payload != b'':
        print(">> source: %s with port: %s" % (ip_object.source_address, tcp_object.src_port))
        print(">> destination: %s with port: %s" % (ip_object.destination_address, tcp_object.dst_port))
        print(">> data: ", tcp_object.payload.decode())
        print("--------------------------------------------------------")


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)
    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    tcp_number = 0x0006
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, tcp_number)
    while True:
        packet, address = stealer.recvfrom(4096)
        ip_object = parsing_ip_packet(packet)
        tcp_object = parsing_tcp_packet(ip_object.payload)
        display(ip_object, tcp_object)


if __name__ == "__main__":
    main()