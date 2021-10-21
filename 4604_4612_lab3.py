import binascii
import socket


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    raw_ip_addr = '.'.join(str(c) for c in raw_ip_addr)
    return raw_ip_addr


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    #ip_packet_payload=binascii.hexlify(ip_packet_payload)
    #src_port = ip_packet_payload[0:4]
    #ip_packet_payload = binascii.hexlify(ip_packet_payload)
    #source_port = int(ip_packet_payload[0:4], 16)
    #destination_port = int(ip_packet_payload[4:8], 16)
    #data_offset = int(ip_packet_payload[24:25], 16)
    #ip_packet_payload = binascii.unhexlify(ip_packet_payload)
    #payload = ip_packet_payload[32:]
    src_port=int.from_bytes(ip_packet_payload[0:2], byteorder='big')
    dest_port=int.from_bytes(ip_packet_payload[2:4], byteorder='big')
    condition = 0b11110000
    placeholder= int.from_bytes(ip_packet_payload[12:13], byteorder='big')
    placeholder= placeholder & condition
    data_offset = placeholder >> 4
    payload= ip_packet_payload[32:]
    message=payload.decode()
    print(message)
    return TcpPacket(src_port, dest_port, data_offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    #ip_packet = binascii.hexlify(ip_packet)
    #IHL = int(ip_packet[1:2], 16)
    #ip_packet = binascii.unhexlify(ip_packet)
    condition = 0b00001111
    IHL = ip_packet[0] & condition
    protocol = ip_packet[9]
    source_address = parse_raw_ip_addr(ip_packet[12:16])
    destination_address = parse_raw_ip_addr(ip_packet[16:20])
    payload = ip_packet[20:]
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    return IpPacket(protocol, IHL, source_address, destination_address, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    TCP = 0x006
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP)
    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                  socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        # Receive packets and do processing here
        packet, address = stealer.recvfrom(4096)
        print(packet)
        parse_raw_ip_addr(address)

        parsed_packet_hex_ip = parse_network_layer_packet(packet)
        print(parsed_packet_hex_ip)
        payload = parse_application_layer_packet(parsed_packet_hex_ip.payload)
        print(payload)

        pass
    pass


if __name__ == "__main__":
    main()