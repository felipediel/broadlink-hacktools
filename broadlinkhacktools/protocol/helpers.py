"""Helper functions."""
from zlib import adler32

from .const import Command, PacketType


def check_integrity(packet):
    """Check the integrity of a packet."""
    checksum = int.from_bytes(packet.checksum, 'little')
    if adler32(packet, 0xbeaf) & 0xffff - sum(packet.checksum) - checksum:
        return False
    return True

def get_packet_type(command):
    """Get packet type."""
    unencrypted = [
        Command.DISCOVER_REQUEST,
        Command.DISCOVER_RESPONSE,
        Command.HELLO_REQUEST,
        Command.HELLO_RESPONSE
    ]

    if command in unencrypted:
        return PacketType.PRIVATE_PACKET
    return PacketType.PUBLIC_PACKET
