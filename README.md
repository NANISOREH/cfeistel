# cfeistel
Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.

As of now, it operates on 16 bytes blocks and an 8 bytes key, in CBC mode. '0' padding is applied both to blocks and key if needed. I plan on implementing more modes of operation and a proper padding handling.

The "f" part of the cipher has no real cryptographic value but still serves the purpose of showing a Feistel cipher in motion. It aspires to be a very simple SP network, I don't know if it can't be defined as one right now.

# Installation
Clone this repo, cd into it and `make cfeistel`. Make sure you have make installed.

# Usage
Command synopsis:

`./cfeistel [-k key][-in infile][-out outfile][-mode mode]`

If parameters are not specified default values are used. 
"in" is the default input file, "out" is the default output file, "defaultk" is the default key value and "enc" is the default mode.

Selectable modes are:
- `enc` for encryption in CBC mode
- `dec` for decryption in CBC mode

The -mode parameter will probably work differently when I'll implement more modes of operation.

