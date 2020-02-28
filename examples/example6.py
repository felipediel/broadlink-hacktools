"""Obtain the device key from one sequence to decrypt the other."""
import errno
import os

from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.filter import CommandSpec
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY, Command


# Load packets with a known client key.
src_folder = 'samples/felipediel/0x2787-v20025-homeassistant'
packets = PersistenceHandler.load_packets(src_folder)

# Decrypt packets.
decryptor = PacketDecryptor(DEFAULT_KEY, DEFAULT_IV)
decryptor.decrypt(packets)

# Filter packets to get auth response.
spec = CommandSpec(Command.AUTH_RESPONSE)
auth_response = next(filter(spec, packets))

# Obtain device key from auth response.
stolen_key = PacketDecryptor.get_key(auth_response)

# Load packets with a different client key (same device).
src_folder = 'samples/felipediel/0x2787-v55-broadlinkapp'  # TODO
packets = PersistenceHandler.load_packets(src_folder)

# Decrypt packets with the stolen key.
decryptor = PacketDecryptor(stolen_key, DEFAULT_IV)
decryptor.decrypt(packets)

# Create 'example6' folder.
try:
    os.makedirs('example6')
except OSError as error:
    if error.errno != errno.EEXIST:
        raise

# Print packets
printer = PacketPrinter()
with open('example6/packets.txt', 'w+') as file:
    for packet in packets:
        printer.print(packet, file=file)
