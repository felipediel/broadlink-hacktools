"""Eliminating duplicates from a large set of packets."""
import errno
import os

from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.filter import NoDuplicatePacketSpec, NoDuplicateValueSpec
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY, Command


# Load packets from multiple folders.
folders = [
    os.path.join('samples', 'siytek', '0x5f36-v44057-broadlinkapp'),
    os.path.join('samples', 'siytek', '0x5f36-v44057-broadlinkapp-02'),
    os.path.join('samples', 'siytek', '0x5f36-v44057-broadlinkapp-03'),
    os.path.join('samples', 'siytek', '0x5f36-v44057-broadlinkapp-04')
]
samples = [PersistenceHandler.load_packets(folder) for folder in folders]
packets = [packet for packets in samples for packet in packets]

# Create 'example5' folder.
try:
    os.makedirs('example5')
except OSError as error:
    if error.errno != errno.EEXIST:
        raise

# Print packets.
printer = PacketPrinter()
dest_file = os.path.join('example5', 'no-filter.txt')
with open(dest_file, 'w+') as file:
    for packet in packets:
        printer.print(packet, file=file)

# Print packets eliminating duplicate packets and commands.
dest_file = os.path.join('example5', 'no-duplicate.txt')
with open(dest_file, 'w+') as file:
    no_duplicate_packets = NoDuplicatePacketSpec()
    no_duplicate_commands = NoDuplicateValueSpec('command')
    spec = lambda x: no_duplicate_packets(x) and no_duplicate_commands(x)

    for packet in filter(spec, packets):
        printer.print(packet, file=file)
