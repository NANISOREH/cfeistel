# cfeistel
Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.

As of now, it operates on 16 bytes blocks and an 8 bytes key, in CBC mode. '0' padding is applied both to blocks and key if needed. I plan on implementing more modes of operation and a proper padding handling.

The "f" part of the cipher has no real cryptographic value but still serves the purpose of showing a Feistel cipher in motion. It aspires to be a very simple SP network, I don't know if it can't be defined as one right now.

# Installation
Clone this repo, cd into it and `make cfeistel`. Make sure you have make installed.

# Usage
Synopsis:

`./cfeistel enc [-k key][-in infile][-out outfile][-mode ]`
`./cfeistel dec [-k key][-in infile][-out outfile][-mode ]`

If parameters are not specified default values are used. 
"in" is the default input file, "out" is the default output file, "defaultk" is the default key value and "ecb" is the default mode.

Selectable modes are:
- `ecb`
- `cbc` 
