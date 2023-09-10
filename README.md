# cfeistel
<p>Implementation of a basic Feistel cipher in C. Needless to say, it's just an exercise and NOT intended to be used as actual crypto.
It operates on 16 bytes blocks and an 8 bytes key, in CBC, ECB and CTR mode, on files of any size.
The key is given as an input string as of now, but I'm going to make it possible to specify a file as key.</p>
<p>The "f" part of the cipher has no real cryptographic value but still serves the purpose of showing a Feistel cipher in motion. It aspires to be a very simple SP network.</p>
<p>I plan on implementing more modes of operation and a proper padding scheme and/or ciphertext stealing. 
ECB, CTR and CBC (decryption only) allow parallel processing.</p>

# Installation
<p>Clone this repo, cd into it and <code>make</code>. Make sure you have make (and a C compiler) installed.
Note that I may have used some Linux-specific functions to log processing progress, so it might refuse to compile anywhere else for now.</p>
<p>Optionally, you can pass the <code>DEBUG</code> compiler flag by means of <code>make CFLAGS="-DDEBUG"</code> to get block-by-block logging, useful on very small inputs to debug the cipher's logic and multithreading.<br>
The <code>SEQ</code> compiler flag disables parallelization and executes the cipher sequentially.<br>
The <code>QUIET</code> compiler flag disables the usual info output.</p>

# Usage
`./cfeistel enc|dec [-k key][-i infile][-o outfile][-m mode]`

- `-k` specifies a string to be used as a key.
- `-m` accepts *ecb*, *cbc*, and *ctr*.
- `-i` specifies the input file to be encrypted or decrypted.
- `-o` specifies the output file where the result will be written.

If no parameters are specified default values are used.
<em>in</em> is the default input file, <em>out</em> is the default output file, <em>secretkey</em> is the default key value and <em>ctr</em> is the default mode.<br>
In case the user specifies an input file but not an output file, the source will be replaced with the encrypted file.<br>

# Test script
I included a shell script that greatly facilitates testing, by automatically compiling the program, creating a file of any desired size, performing encryption and decryption and comparing the md5 checksum of the result against pre-encyption data to determine if the process worked as it should.

Usage: <code>./test.sh [-mb] <file_size> [-m <mode>] [debug]</code>

- `file_size` specifies the size of the file that the script will generate expressed, by default, in bytes
- `-mb` specifies a file size in MBs rather than in bytes.
- `-m` specifies which operation mode to test, and accepts the same modes as the cfeistel executable.
- `debug` enables block-by-block logging and redirects the logging output to a text file.

# Known issues
- As of now, the cipher in any mode won't work properly if the input file size is an exact multiple of the buffer size I chose (100MB, or 104857600 bytes).
- The IV generation for CBC and CTR modes is basicly just a placeholder for now. It's simply derived from the key, so it's neither random nor unpredictable. This cipher does not aspire to be actually <em>secure</em>, but I'd still like to provide a decent approximation of how a cryptographically sound Feistel cipher might look like.
- Command selection is pretty messy and probably really easy to break. There's probably plenty of libraries that implement off-the-shelf command selection for POSIX-y programs, I should look into that rather than build on my own undercooked spaghetti. 