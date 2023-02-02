# cfeistel
<p>Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.
It operates on 16 bytes blocks and an 8 bytes key, in CBC, ECB and CTR mode, on files of any size.</p>
<p>The "f" part of the cipher has no real cryptographic value but still serves the purpose of showing a Feistel cipher in motion. It aspires to be a very simple SP network.</p>
<p>I plan on implementing more modes of operation and a proper padding scheme and/or ciphertext stealing. I'm also looking into ways to parallelize the workload for the modes of operation that allow parallel computing to gain some performance. </p>

# Installation
<p>Clone this repo, cd into it and `make cfeistel`. Make sure you have make installed.</p>

# Usage
Encryption:
`./cfeistel enc [-k key][-i infile][-o outfile][-m mode]`

Decryption:
`./cfeistel dec [-k key][-i infile][-o outfile][-m mode]`

<p>If no parameters are specified default values are used. 
<em>in</em> is the default input file, <em>out</em> is the default output file, <em>secretkey</em> is the default key value and <em>ctr</em> is the default mode.
In case the user specifies an input file but not an output file, the source will be replaced with the encrypted file.
The -k accepts a string to be used as a key.
The -m parameter accepts <em>ecb</em>, <em>cbc</em> and <em>ctr</em>.

You can add -v to enable some block-by-block logging for the operation to perform.</p>