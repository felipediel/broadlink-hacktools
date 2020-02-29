"""Filtering packets."""
import errno
import os

from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.filter import CommandSpec
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY, Command


# Load packets from binary files.
src_folder = os.path.join('samples', 'felipediel', '0x2787-v20025-homeassistant')
packets = PersistenceHandler.load_packets(src_folder)

# Decrypt packets using default key.
decryptor = PacketDecryptor(DEFAULT_KEY, DEFAULT_IV)
decryptor.decrypt(packets)

# Create 'example2' folder.
try:
    os.makedirs('example2')
except OSError as error:
    if error.errno != errno.EEXIST:
        raise

# Print packets to a file.
printer = PacketPrinter()
dest_file = os.path.join('example2', 'no-filter.txt')
with open(dest_file, 'w+') as file:
    for packet in packets:
        printer.print(packet, file=file)

# Filter packets and print auth response only.
dest_file = os.path.join('example2', 'auth-response.txt')
with open(dest_file, 'w+') as file:
    spec = CommandSpec(Command.AUTH_RESPONSE)
    for packet in filter(spec, packets):
        printer.print(packet, file=file)

# Filter packets and print command requests and responses.
dest_file = os.path.join('example2', 'command-requests-and-responses.txt')
with open(dest_file, 'w+') as file:
    command_request = CommandSpec(Command.COMMAND_REQUEST)
    command_response = CommandSpec(Command.COMMAND_RESPONSE)
    spec = lambda x: command_request(x) or command_response(x)
    for packet in filter(spec, packets):
        printer.print(packet, file=file)
