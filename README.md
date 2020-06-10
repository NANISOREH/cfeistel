# cfeistel
<p>Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.
As of now, it operates on 16 bytes blocks and an 8 bytes key, in CBC, ECB and CTR mode, on files with a maximum size of 160mb. '0' padding is applied both to blocks and key if needed. I plan on implementing more modes of operation and a proper padding scheme. </p>

<p>The "f" part of the cipher has no real cryptographic value but still serves the purpose of showing a Feistel cipher in motion. It aspires to be a very simple SP network.</p>

# Installation
<p>Clone this repo, cd into it and `make cfeistel`. Make sure you have make installed.</p>

# Usage
Encryption:
`./cfeistel enc [-k key][-in infile][-out outfile][-m mode]`

Decryption:
`./cfeistel dec [-k key][-in infile][-out outfile][-m mode]`

<p>If parameters are not specified default values are used. 
<em>in</em> is the default input file, <em>out</em> is the default output file, <em>secretkey</em> is the default key value and <em>ctr</em> is the default mode. The -m parameter accepts <em>ecb</em>, <em>cbc</em> and <em>ctr</em>.

You can add -v to enable some block-by-block logging for the operation to perform.</p>