"""Constant values."""
from enum import Enum, IntEnum, auto, unique

DEFAULT_KEY = bytes(
    [
        0x09,
        0x76,
        0x28,
        0x34,
        0x3F,
        0xE9,
        0x9E,
        0x23,
        0x76,
        0x5C,
        0x15,
        0x13,
        0xAC,
        0xCF,
        0x8B,
        0x02
    ]
)
DEFAULT_IV = bytes(
    [
        0x56,
        0x2E,
        0x17,
        0x99,
        0x6D,
        0x09,
        0x3D,
        0x28,
        0xDD,
        0xB3,
        0xBA,
        0x69,
        0x5A,
        0x2E,
        0x6F,
        0x58
    ]
)


@unique
class PacketType(Enum):
    """Packet type."""
    PUBLIC_PACKET = auto()
    PRIVATE_PACKET = auto()


@unique
class Command(IntEnum):
    """Command."""
    HELLO_REQUEST = 0x6
    DISCOVER_REQUEST = 0x1a
    JOIN_REQUEST = 0x14
    AUTH_REQUEST = 0x65
    COMMAND_REQUEST = 0x6a
    
    HELLO_RESPONSE = 0x7
    DISCOVER_RESPONSE = 0x1b
    JOIN_RESPONSE = 0x15
    AUTH_RESPONSE = 0x3e9
    COMMAND_RESPONSE = 0x3ee
