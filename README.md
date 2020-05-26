# cfeistel
Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.

As of now, it operates on a single block of input data. If data and/or key are exceeding in size, the excess part is discarded; if they're too short, '0' padding is applied. I plan on implementing proper operation modes, padding handling and user-selectable block size and key size.

The "f" part of the cipher is still basicly a placeholder, it just does a byte-by-byte sum between the key and the right part of the block, so it has no real cryptographic value but still serves the purpose of showing how a Feistel cipher works. I plan on replacing it with a simple one-way function for the sake of "realism".

# Installation
Clone this repo, cd into it and `make cfeistel`. Make sure you have make installed.

# Usage
Command synopsis:

`./cfeistel [-k key][-in infile][-out outfile]`

If not specified, all three parameters have a default fallback value.
