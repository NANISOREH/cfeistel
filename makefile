CFLAGS=
CPPFLAGS=-fopenmp -lssl -lcrypto

cfeistel: src/main.o src/utils.o src/feistel.o src/opmodes.o src/block.o
		gcc src/main.o src/utils.o src/feistel.o src/opmodes.o src/block.o $(CFLAGS) -fopenmp -lssl -lcrypto -o cfeistel
		rm src/main.o src/utils.o src/feistel.o src/opmodes.o src/block.o  

utils.o: src/utils.c
		gcc -c src/utils.c

main.o: src/main.c
		gcc -c src/main.c 

feistel.o: src/feistel.c
		gcc -c src/feistel.c

opmodes.o: src/opmodes.c
		gcc -c src/opmodes.c 

block.o: src/block.c
		gcc -c src/block.c