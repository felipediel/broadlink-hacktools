"""Grouping packets by command and printing results."""
import errno
import os

from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.filter import CommandSpec
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY, Command


# Load samples.
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

# Decrypt packets.
for packets in samples:
    decryptor = PacketDecryptor(DEFAULT_KEY, DEFAULT_IV)
    decryptor.decrypt(packets)

# Create 'example4' folder.
try:
    os.makedirs('example4')
except OSError as error:
    if error.errno != errno.EEXIST:
        raise

# Group packets by command and print results.
printer = PacketPrinter()
command_files = [
    (Command.AUTH_REQUEST, os.path.join('example4', 'auth-requests.txt')),
    (Command.AUTH_RESPONSE, os.path.join('example4', 'auth-responses.txt')),
    (Command.COMMAND_REQUEST, os.path.join('example4', 'command-requests.txt')),
    (Command.COMMAND_RESPONSE, os.path.join('example4', 'command-responses.txt')),
    (Command.DISCOVER_REQUEST, os.path.join('example4', 'discover-requests.txt')),
    (Command.DISCOVER_RESPONSE, os.path.join('example4', 'discover-responses.txt')),
    (Command.HELLO_REQUEST, os.path.join('example4', 'hello-request.txt')),
    (Command.HELLO_RESPONSE, os.path.join('example4', 'hello-response.txt')),
    (Command.JOIN_REQUEST, os.path.join('example4', 'join-request.txt')),
    (Command.JOIN_RESPONSE, os.path.join('example4', 'join-response.txt'))
]
for command, filename in command_files:
    results = []
    spec = CommandSpec(command)
    for index, packets in enumerate(samples):
        packet = next(filter(spec, packets), None)
        if packet is not None:
            results.append((index, packet))

    with open(filename, 'w+') as file:
        for index, packet in results:
            print(folders[index], file=file)
            printer.print(packet, file=file)
