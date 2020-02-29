"""Support for persisting packets."""
import errno
from logging import getLogger
import os

from .protocol.helpers import check_integrity
from .protocol.packets import PacketFactory

_LOGGER = getLogger(__name__)


class PersistenceHandler:
    """Persist packets."""

    @staticmethod
    def load_packets(folder, check=False):
        """Load a sequence of packets from a folder."""
        is_binary_file = lambda x:x.endswith((".bin"))
        packet_number = lambda x: int(''.join(filter(str.isdigit, x)))
        filenames = sorted(filter(is_binary_file, os.listdir(folder)), key=packet_number)

        packets = []
        for index, filename in enumerate(filenames):
            with open(os.path.join(folder, filename), 'rb') as file:
                packet = PacketFactory.from_file(file)
                if check and not check_integrity(packet):
                    _LOGGER.error("Failed to load packet %d: checksum error", index)
                    continue
                packets.append(packet)
        return packets

    @staticmethod
    def store_packets(packets, folder):
        """Store a sequence of packets into a folder."""
        try:
            os.makedirs(folder)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise

        for index, packet in enumerate(packets):
            with open(os.path.join(folder, f'{index}.bin'), 'wb') as file:
                file.write(packet.get_bytes())
