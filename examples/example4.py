"""Grouping packets by command and printing results."""
import errno
import os

from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.filter import CommandSpec
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY, Command


# Load samples.
folders = [
    'samples/felipediel/0x2787-v20025-homeassistant',
    'samples/bbreton09/0x5f36-v44057-debug',
    'samples/elafargue/0x5f36-v44057-testsolution2',
    'samples/dennisadvani/0x5f36-v44057-testsolution3',
    'samples/turlubullu/0x5f36-v44057-testsolution3',
    'samples/InToSSH/0x5f36-v44057-testsolution3',
    'samples/luisfosoares/0x5f36-v44057-testsolution4',
    'samples/nickollasaranha/0x5f36-v44057-testsolution4'
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
    (Command.AUTH_REQUEST, 'example4/auth_requests.txt'),
    (Command.AUTH_RESPONSE, 'example4/auth_responses.txt'),
    (Command.COMMAND_REQUEST, 'example4/command_requests.txt'),
    (Command.COMMAND_RESPONSE, 'example4/command_responses.txt'),
    (Command.DISCOVER_REQUEST, 'example4/discover_requests.txt'),
    (Command.DISCOVER_RESPONSE, 'example4/discover_responses.txt'),
    (Command.HELLO_REQUEST, 'example4/hello_request.txt'),
    (Command.HELLO_RESPONSE, 'example4/hello_response.txt'),
    (Command.JOIN_REQUEST, 'example4/join_request.txt'),
    (Command.JOIN_RESPONSE, 'example4/join_response.txt') 
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
