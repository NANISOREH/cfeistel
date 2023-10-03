# cfeistel
<p>Implementation of a basic Feistel cipher in C. Needless to say, it's just a glorified C programming exercise and NOT intended to be used as actual crypto.
It operates on 16 bytes blocks and an 8 bytes key, in CBC, PCBC, ECB, OFB, CFB and CTR mode, on files of any size.
The key is given as an input string as of now, but I'm going to make it possible to specify a file as key. You can input a key of any size, and PBKDF2 will shrink it into an 8 byte key.</p>
<p>The "f" part of the cipher has no real cryptographic value but still serves the purpose of showing a Feistel cipher in motion. It aspires to be a very simple SP network.</p>
<p>I plan on implementing more modes of operation and a proper padding scheme and/or ciphertext stealing. 
ECB, CTR, CFB (decryption only) and CBC (decryption only) allow parallel processing.</p>

# Installation
<p>Clone this repo, cd into it and <code>make</code>.

Requirements:
- `make` and `gcc`.
- `libssl-dev`, which is only used for key derivation.

Note that I may have used some Linux-specific functions to log processing progress, so it might refuse to compile anywhere else for now.</p>
<p>Optionally, you can pass the <code>DEBUG</code> compiler flag by means of <code>make CFLAGS="-DDEBUG"</code> to get block-by-block logging, useful on very small inputs to debug the cipher's logic and multithreading.<br>
The <code>SEQ</code> compiler flag disables parallelization and executes the cipher sequentially.<br>
The <code>QUIET</code> compiler flag disables the usual info output.</p>

# Usage
`./cfeistel <enc|dec> [-k <key>] [-i <infile>] [-o <outfile>] [-m <mode>]`

- `enc` provides encryption and `dec` provides decryption.  
- `-k <key>` specifies a string to be used as a key.
- `-m <mode>` specifies the mode of operation, and accepts *ecb*, *cbc*, *pcbc*, *ctr*, *ofb*, *cfb*.
- `-i <infile>` specifies the input file to be encrypted or decrypted.
- `-o <outfile>` specifies the output file where the result will be written.

If no parameters are specified default values are used.
<em>in</em> is the default input file, <em>out</em> is the default output file, <em>secretkey</em> is the default key value and <em>ctr</em> is the default mode.<br>

# Test script
I included a shell script that greatly facilitates testing, by automatically compiling the program, creating a file of any desired size, performing encryption and decryption and comparing the md5 checksum of the result against pre-encyption data to determine if the process worked as it should.

Usage: <code>./test.sh [-mb] [-d] [-dp] [-t] [-r] [-s] <file_size> [-m <mode>] [-k <key>] [-dk <dec_key>] [-ek <enc_key>] </code>

- `-mb` specifies that the given file size is expressed in MBs rather than in bytes.
- `-d` disables parallel execution and enables block-by-block logging, redirecting the logs of encryption and decryption to text files.
- `-dp` behaves like `-d` but keeps parallel execution enabled. The two debugging options are obviously mutually exclusive.
- `-t` makes the script perform encryption and decryption on a human-readable text file instead of reading random bytes from /dev/urandom.
- `-r` makes the script create a file where the same content is repeated for every 16 bytes block, in order to test block dependency propagation (or lack thereof).
- `-s` launches a test suite covering a selection of relevant filesizes. Enabling it will make the script ignore your filesize, file type and debug options, but it will still respect your mode and key options.
- `<file_size>` specifies the size of the file that the script will generate (default value: 16 bytes). 
- `-m <mode>` specifies which operation mode to test, and accepts the same modes as the cfeistel executable (default value: <em>ctr</em>).
- `-k <key>` specifies the key string to use for both encryption and decryption (default value: <em>secretkey</em>).
- `-dk <dec_key>` specifies the key string to use for decryption (default value: <em>secretkey</em>).
- `-ek <enc_key>` specifies the key string to use for encryption (default value: <em>secretkey</em>).

Note that `-d` and `-t` options will only be accepted if the set size is 1mb (1048576 bytes) or less. This will avoid the creation of huge text files that would both make your text editor cry in pain and defeat the purpose of printing these stuff out in the first place.<br> 
In case `-d` and `-t` are used together, both the generated text file and the result of the decryption will be appended to the log files.

# Known issues
- As I already touched upon, the "f" black box that implements the SP network is made with a <em>just do something</em> mentality. It parrots DES a little bit. I do intend on studying what makes an SP network cryptographically sound and how to design one that's a bit more thought out.
- Key derivation is taken off the shelf via the PBKDF2 implementation of the OpenSSL C library. While obviously being the best thing I could possibly do, it's also extremely weird. You're literally linking a library that implements actual cryptography to a binary that does a way worse job at the same task. So, yeah, I'd like to implement a makeshift key derivation function myself and remove the OpenSSL dependency. 