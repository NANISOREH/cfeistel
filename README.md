# cfeistel
Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.

As of now, it operates on 16 bytes blocks and an 8 bytes key. '0' padding is applied both to blocks and key if needed. I plan on implementing proper operation modes, padding handling and user-selectable block size and key size.

The "f" part of the cipher is still basicly a placeholder, it just does some byte-by-byte arithmetic to shuffle things around so it has no real cryptographic value but still serves the purpose of showing how a Feistel cipher works. I plan on replacing it with a simple SP network.

# Installation
Clone this repo, cd into it and `make cfeistel`. Make sure you have make installed.

# Usage
Command synopsis:

`./cfeistel [-k key][-in infile][-out outfile]`

If parameters are not specified default values are used. 
"in" is the default input file, "out" is the default output file and "defaultk" is the default key value.

