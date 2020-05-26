# cfeistel
Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.

# Installation
Clone this repo, cd into it and `make cfeistel`. Make sure you have make installed.

# Usage
As of now, it operates on a single block of input data. If data and/or key are exceeding in size, the excess part is discarded; if they're too short, '0' padding is applied.

Command synopsis:

`./cfeistel [-k key][-in infile][-out outfile]`

If not specified, all three parameters have a default fallback value.
