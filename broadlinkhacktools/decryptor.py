"""Support for decrypting packets."""
from logging import getLogger

from .protocol.const import Command

_LOGGER = getLogger(__name__)


class PacketDecryptor:
    """Broadlink packet decryptor."""

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def decrypt(self, packets):
        """Intercept key and decrypt a sequence of packets."""
        for index, packet in enumerate(packets):
            try:
                packet.decrypt(self.key, self.iv)
            except ValueError:
                _LOGGER.error("Failed to decrypt packet %d: invalid key", index)
                continue
            
            command = int.from_bytes(packet.command, 'little')
            if command == Command.AUTH_RESPONSE:
                key = self.get_key(packet)
                if not key or len(key) % 16:
                    message = f"Invalid key intercepted in packet {index}: {key}"
                    _LOGGER.error(message)
                else:
                    message = f'Key intercepted in packet {index}: {key}'
                    _LOGGER.info(message)
                    self.key = key

    @staticmethod
    def get_key(packet):
        """Get key from an auth response packet."""
        return packet.payload[0x04:0x14]
