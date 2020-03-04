"""Obtain the device key from one sequence to decrypt the other."""
import errno
import os

from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.filter import CommandSpec
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY, Command


# Load packets with a known client key.
src_folder = os.path.join('samples', 'dennisadvani', '0x5f36-v44057-debug')
packets = PersistenceHandler.load_packets(src_folder)
print(len(packets))

# Decrypt packets.
decryptor = PacketDecryptor(DEFAULT_KEY, DEFAULT_IV)
decryptor.decrypt(packets)

# Filter packets to get auth response.
spec = CommandSpec(Command.AUTH_RESPONSE)
auth_response = next(filter(spec, packets))

# Obtain device key from auth response.
stolen_key = PacketDecryptor.get_key(auth_response)
print(stolen_key)

# Load packets with a different client key (same device).
src_folder = os.path.join('samples', 'dennisadvani', '0x5f36-v44057-broadlinkapp')
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
dest_file = os.path.join('example6', 'packets.txt')
with open(dest_file, 'w+') as file:
    for packet in packets:
        printer.print(packet, file=file)
