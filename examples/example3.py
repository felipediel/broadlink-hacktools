"""Working with groups of packets."""
import errno
import os

from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.filter import CommandSpec
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY, Command


# Load samples
folders = [
    os.path.join('samples', 'felipediel', '0x2787-v20025-homeassistant'),
    os.path.join('samples', 'bbreton09', '0x5f36-v44057-debug'),
    os.path.join('samples', 'elafargue', '0x5f36-v44057-testsolution2'),
    os.path.join('samples', 'dennisadvani', '0x5f36-v44057-testsolution3'),
    os.path.join('samples', 'turlubullu', '0x5f36-v44057-testsolution3'),
    os.path.join('samples', 'InToSSH', '0x5f36-v44057-testsolution3'),
    os.path.join('samples', 'luisfosoares', '0x5f36-v44057-testsolution4'),
    os.path.join('samples', 'nickollasaranha', '0x5f36-v44057-testsolution4')
]
samples = [PersistenceHandler.load_packets(folder) for folder in folders]

# Decrypt packets
for packets in samples:
    decryptor = PacketDecryptor(DEFAULT_KEY, DEFAULT_IV)
    decryptor.decrypt(packets)

# Filter samples to get auth responses only
auth_responses = []
spec = CommandSpec(Command.AUTH_RESPONSE)
for index, packets in enumerate(samples):
    packet = next(filter(spec, packets), None)
    if packet is not None:
        auth_responses.append((index, packet))

# Create 'example3' folder.
try:
    os.makedirs('example3')
except OSError as error:
    if error.errno != errno.EEXIST:
        raise

# Print results to a file
printer = PacketPrinter()
dest_file = os.path.join('example3','auth-responses.txt')
with open(dest_file, 'w+') as file:
    for index, packet in auth_responses:
        print(folders[index], file=file)
        printer.print(packet, file=file)
