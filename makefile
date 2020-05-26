cfeistel: src/main.o src/utils.o src/feistel.o 
		gcc src/main.o src/utils.o src/feistel.o -o cfeistel
		rm src/main.o src/utils.o src/feistel.o 

utils.o: src/utils.c
		gcc -c src/utils.c

main.o: src/main.c
		gcc -c src/main.c

feistel.o: src/feistel.c
		gcc -c src/feistel.c
