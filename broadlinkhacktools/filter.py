"""Support for filtering packets."""
from abc import ABC, abstractmethod

from .protocol.const import Command


class PacketSpecABC(ABC):
    """Representation of a packet specification."""

    @abstractmethod
    def __call__(self, packet):
        """Return True if the packet satisfies the specification."""
        pass


class CommandSpec(PacketSpecABC):
    """Specification of a command."""

    def __init__(self, command):
        """Initialize the specification."""
        self.command = command

    def __call__(self, packet):
        """Return True if the packet contains the specified commmand."""
        command = int.from_bytes(packet.command, 'little')
        return command == self.command


class NoDuplicatePacketSpec(PacketSpecABC):
    """Specification of a packet sequence without duplicate packets."""

    def __init__(self):
        """Initialize the specification."""
        self._packets = []

    def __call__(self, packet):
        """Return True if the packet is not a duplicate."""
        if packet in self._packets:
            return False
        self._packets.append(packet)
        return True


class NoDuplicateValueSpec(PacketSpecABC):
    """Specification of a packet sequence without duplicate values for an attribute."""
    def __init__(self, attribute):
        self.attribute = attribute
        self._values = []

    def __call__(self, packet):
        """Return True if the value is not a duplicate."""
        value = getattr(packet, self.attribute)
        if value in self._values:
            return False
        self._values.append(value)
        return True
