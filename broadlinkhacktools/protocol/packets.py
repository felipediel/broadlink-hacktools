"""Support for Broadlink packets."""
from abc import ABC, abstractmethod
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from io import SEEK_CUR, BytesIO
from zlib import adler32

from .const import Command, PacketType
from .helpers import get_packet_type


class PacketABC(ABC):
    """Representation of a packet."""
    
    def __init__(self, data):
        """Initialize the packet."""
        self._data = data

    def __str__(self):
        """String representation of the packet."""
        return format(self._data, 'x')

    def __len__(self):
        """Length of the packet."""
        return len(self._data)

    def __eq__(self, other):
        """Equal operator."""
        return self.get_bytes() == other.get_bytes()

    def __getitem__(self, index):
        """Get a value."""
        return self._data[index]
    
    def __setitem__(self, index, value):
        """Set a value."""
        self._data[index] = value
    
    def __format__(self, value):
        """Format the packet."""
        if value == 'i':
            return ' '.join(list(self._data))
        if value == 'x':  # TODO REGEX {02X}
            return ' '.join(format(byte, '02x') for byte in self._data)
        return str(self._data)
    
    def get_bytes(self):
        """Get representation in bytes."""
        return self._data

    def get_info(self):
        """Get dictionary of attributes."""
        return {
		    attr: getattr(self, attr)
		    for attr in dir(self)
		    if hasattr(type(self), attr)
		    and isinstance(getattr(type(self), attr), property)
		}


class PacketHeader(PacketABC):
    """Representation of a packet header."""

    @property
    def checksum(self):
        """Checksum."""
        return self._data[0x00:0x08]

    @property
    def gmt_offset(self):
        """GMT offset."""
        return self._data[0x08:0x0c]
    
    @property
    def year(self):
        """Year."""
        return self._data[0x0c:0x0e]
    
    @property
    def seconds(self):
        """Seconds."""
        return self._data[0x0e]
    
    @property
    def minutes(self):
        """Minutes."""
        return self._data[0x0f]
    
    @property
    def hours(self):
        """Hours."""
        return self._data[0x10]

    @property
    def day_of_the_week(self):
        """Day of the week."""
        return self._data[0x11]

    @property
    def day_in_month(self):
        """Day in month."""
        return self._data[0x12]
    
    @property
    def month(self):
        """Month."""
        return self._data[0x13]
    
    @property
    def padding(self):
        """Padding."""
        return self._data[0x14:0x18]

    @property
    def client_addr(self):
        """Client address."""
        return self._data[0x18:0x1c]
    
    @property
    def client_port(self):
        """Client port."""
        return self._data[0x1c:0x1e]
    
    def get_info(self):
        """Get dictionary of attributes."""
        return {
            'Checksum': self.checksum,
            'GMT offset': self.gmt_offset,
            'Year': self.year,
            'Seconds': self.seconds,
            'Minutes': self.minutes,
            'Hours': self.hours,
            'Day of the week': self.day_of_the_week,
            'Day in month': self.day_in_month,
            'Month': self.month,
            'Padding': self.padding,
            'Client address': self.client_addr,
            'Client port': self.client_port
        }


class BroadlinkPacket(PacketABC):
    """Representation of a Broadlink packet."""
    
    def __init__(self, data):
        """Initialize the packet."""
        super().__init__(data)
        self._header = PacketHeader(self._data[:0x20])

    @property
    def header(self):
        """Header."""
        return self._header

    @property
    def checksum(self):
        """Checksum."""
        return self._data[0x20:0x22]

    @property
    def error(self):
        """Error code."""
        return self._data[0x22:0x24]

    @property
    def device_type(self):
        """Device type."""
        return self._data[0x24:0x26]
    
    @property
    def command(self):
        """Command."""
        return self._data[0x26:0x28]

    @property
    def counter(self):
        """Counter."""
        return self._data[0x28:0x2A]

    @property
    def mac_addr(self):
        """MAC address."""
        return self._data[0x2A:0x30]

    def get_info(self):
        """Get dictionary of attributes."""
        return {
            'Header': self.header,
            'Checksum': self.checksum,
            'Error': self.error,
            'Device type': self.device_type,
            'Command': self.command,
            'Counter': self.counter,
            'MAC address': self.mac_addr
        }

    def decrypt(self, key, iv):
        """Decrypt the payload."""
        pass


class PublicPacket(BroadlinkPacket):

    def __init__(self, data):
        """Initialize the packet."""
        super().__init__(data)
        self._payload = None

    @property
    def device_id(self):
        """Device ID."""
        return self._data[0x30:0x34]

    @property
    def payload_checksum(self):
        """Payload checksum."""
        return self._data[0x34:0x36]

    @property
    def encrypted_payload(self):
        """Encrypted payload."""
        return self._data[0x38:]

    @property
    def payload(self):
        """Payload."""
        return self._payload

    def get_info(self):
        """Get dict of attributes."""
        return {
            **super().get_info(),
            'Device ID': self.device_id,
            'Payload checksum': self.payload_checksum,
            'Encrypted payload': self.encrypted_payload,
            'Payload': self.payload
        }

    def decrypt(self, key, iv):
        """Decrypt the payload."""
        aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        payload = decryptor.update(self.encrypted_payload) + decryptor.finalize()
        payload_checksum = int.from_bytes(self.payload_checksum, "little")
        if adler32(payload, 0xbeaf) & 0xffff != payload_checksum:
            raise ValueError
        self._payload = payload


class PrivatePacket(BroadlinkPacket):
    """Representation of a private packet."""

    @property
    def payload(self):
        """Payload."""
        return self._data[0x30:]

    def get_info(self):
        """Get dict of attributes."""
        return {
            **super().get_info(),
            'Payload': self.payload
        }

class PacketFactory:
    """Representation of a packet factory."""

    @staticmethod
    def from_bytes(data):
        """Make packet from bytes."""
        command = int.from_bytes(data[0x26:0x28], 'little')
        packet_type = get_packet_type(command)
        if packet_type == PacketType.PUBLIC_PACKET:
            return PublicPacket(data)
        elif packet_type == PacketType.PRIVATE_PACKET:
            return PrivatePacket(data)
        raise ValueError

    @classmethod
    def from_file(cls, file):
        """Make packet from file."""
        return cls.from_bytes(file.read())
