# Broadlink Hacktools

Broadlink Hacktools is a Python module for decrypting, filtering and analyzing packets captured from Broadlink devices to better integrate them with home automation platforms.

- This is not an official Broadlink application.
- For now, only universal remote devices have are supported.

## Instalation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install broadlinkhacktools.

```bash
pip install broadlinkhacktools
```

## Usage

```python
from broadlinkhacktools import PacketDecryptor, PacketPrinter, PersistenceHandler
from broadlinkhacktools.protocol.const import DEFAULT_IV, DEFAULT_KEY


# Load packets from binary files.
src_folder = 'some_folder'
packets = PersistenceHandler.load_packets(src_folder)

# Decrypt packets using default key.
decryptor = PacketDecryptor(DEFAULT_KEY, DEFAULT_IV)
decryptor.decrypt(packets)

# Print packets to a file.
printer = PacketPrinter()
with open('packets.txt', 'w+') as file:
    for packet in packets:
        printer.print(packet, file=file)

```

For more examples, see *examples* folder.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://github.com/felipediel/broadlink-hacktools/blob/master/LICENSE)
