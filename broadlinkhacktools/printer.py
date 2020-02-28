"""Support for printing packets."""
from enum import IntFlag
from textwrap import wrap

from beautifultable import BeautifulTable


class PrintingMode(IntFlag):
    """Printing mode."""
    BYTES = 0x01
    INFO = 0x02
    DETAILS = 0x04
    ALL = BYTES | INFO | DETAILS


class PacketPrinter:
    """Packet printer."""

    def __init__(self, max_witdh=10000, mode=None):
        """Initialize the printer."""
        self.max_width = max_witdh
        self.mode = (
            PrintingMode.ALL
            if mode is None
            else mode
        )

    def print(self, packet, file=None):
        """Tabulate and print a packet."""
        if self.mode & PrintingMode.INFO:
            table = tabulate_info(packet, self.max_width)
            print(table, file=file)

        if self.mode & PrintingMode.BYTES:
            table = tabulate_bytes(packet, self.max_width)
            print(table, file=file)

        if self.mode & PrintingMode.DETAILS:
            pass  # TODO

        print('', file=file)


def format_hex(obj):
    """Return hexadecimal representation of int or byte object."""
    if obj is None:
        return 'None'
    if hasattr(obj, 'hex'):
        return ' '.join(wrap(obj.hex(), 2))
    return format(obj, '02x')

def tabulate_bytes(packet, max_width):
    """Tabulate bytes of a packet."""
    table = BeautifulTable(max_width=max_width)
    table.column_headers = map(str, range(len(packet)))
    table.append_row([format(byte, '02x') for byte in packet])
    table.append_row(list(packet))
    return table

def tabulate_info(packet, max_width):
    """Tabulate properties of a packet."""
    table = BeautifulTable(max_width=max_width)
    table.column_headers = packet.get_info().keys()
    row = [
        tabulate_info(attr, max_width=max_width/2)
        if hasattr(attr, 'get_info')
        else format_hex(attr)
        for attr in packet.get_info().values()
    ]
    table.append_row(row)
    return table
