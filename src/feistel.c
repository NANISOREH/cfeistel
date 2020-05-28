#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"

//input data handling, starts execution of the cipher
unsigned char * feistel(unsigned char * data, unsigned char * key, enum mode chosen)
{
	int remainder = strlen(data) % BLOCKSIZE;
	unsigned char buffer[BLOCKSIZE];
	int i=0;
	int bcount=0;

	//allocating space for the blocks. 
	block * b;
	if (remainder == 0)		//data size is multiple of the blocksize
		b = (block*)calloc((strlen(data) * sizeof(char) / BLOCKSIZE), sizeof(block));		
	else					//data size is not multiple of the blocksize
		b = (block*)calloc((strlen(data) * sizeof(char) / BLOCKSIZE) + 1, sizeof(block));	

	while (i < strlen(data))
    {
        buffer[i % BLOCKSIZE] = data[i];
        i++;

        if ((i+1) % BLOCKSIZE == 0)		//completed a block
        {
        	buffer[i % BLOCKSIZE] = data[i];
        	i++;
        	for (int j=0; j<BLOCKSIZE/2; j++)	//filling the block with the buffered data
			{
				b[bcount].left[j] = buffer[j];
				b[bcount].right[j] = buffer[j+8];
			}
			//for now, the round key is the same for every round
			//TODO: key scheduling/derivation
			strncpy(b[bcount].round_key, key, KEYSIZE);
			bcount++;

			if (bcount==strlen(data)/BLOCKSIZE)
				break;
        }
    }

    if (remainder>0)	//forming the last 0-padded block, if there's leftover data
    {
    	for (int z=0; z<BLOCKSIZE; z++)		
    	{
    		if (z < remainder)
    			buffer[z] = data[(bcount * BLOCKSIZE) + z];
    		else
    			buffer[z] = '0';
    	}

		for (int y=0; y<BLOCKSIZE/2; y++)
		{
			b[bcount].left[y] = buffer[y];
			b[bcount].right[y] = buffer[y+8];
		}
		strncpy(b[bcount].round_key, key, KEYSIZE);
		bcount++;
    }

    if (chosen == ecb)
    	return operate_ecb_mode(b, bcount);
    else if (chosen == cbc_enc)
    	return encrypt_cbc_mode(b, bcount);
    else if (chosen == cbc_dec)
    	return decrypt_cbc_mode(b, bcount);

    return NULL;
}

//Executes the cipher in ECB mode; takes a block array and the number of blocks, returns processed data.
//it's a bit of a bad ECB, which is amazing, given how ECB is already conceptually bad.
//Thing is, you can't even take advantage of how multithreadable ECB is since i'm not handling concurrency at all
//and that would literally be the only upside of ECB. ¯\_(ツ)_/¯
unsigned char * operate_ecb_mode(block * b, int bnum)
{
	unsigned char * ciphertext;
	int bcount=0;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));

	//launching the feistel algorithm on every block, storing the result in ciphertext
	for (int i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		feistel_block(b[bcount].left, b[bcount].right, b[bcount].round_key);
		for (int j=0; j<BLOCKSIZE; j++)	ciphertext[i+j] = b[bcount].left[j];
		bcount++;
	}

	return ciphertext;
}

unsigned char * encrypt_cbc_mode(block * b, int bnum)
{
	unsigned char * ciphertext;
	block prev_ciphertext;
	int bcount=0;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));

	//prev_ciphertext will start off with the initialization vector
	strcpy(prev_ciphertext.left, "al2ewwed");
	strcpy(prev_ciphertext.right, "12dewccs");

	//launching the feistel algorithm on every block, storing the result in ciphertext
	for (int i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		char_xor(b[bcount].left, b[bcount].left, prev_ciphertext.left);
		char_xor(b[bcount].right, b[bcount].right, prev_ciphertext.right);
		feistel_block(b[bcount].left, b[bcount].right, b[bcount].round_key);
		for (int j=0; j<BLOCKSIZE; j++)	
		{
			ciphertext[i+j] = b[bcount].left[j];
			prev_ciphertext.left[j] = b[bcount].left[j];
		}
		bcount++;
	}

	return ciphertext;
}

unsigned char * decrypt_cbc_mode(block * b, int bnum)
{
	unsigned char * plaintext;
	block prev_ciphertext;
	int bcount=0;
	plaintext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));

	//prev_ciphertext will start off with the initialization vector
	strcpy(prev_ciphertext.left, "al2ewwed");
	strcpy(prev_ciphertext.right, "12dewccs");

	//launching the feistel algorithm on every block, storing the result in plaintext
	for (int i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		memcpy(&prev_ciphertext, &b[bcount], sizeof(block));
		if (i % BLOCKSIZE == 0 && bcount < bnum) 
		{
			feistel_block(b[bcount].left, b[bcount].right, b[bcount].round_key);
			char_xor(b[bcount].left, b[bcount].left, prev_ciphertext.left);
			char_xor(b[bcount].right, b[bcount].right, prev_ciphertext.right);
			for (int j=0; j<BLOCKSIZE; j++)	plaintext[i+j] = b[bcount].left[j];
			bcount++;
		}

	}

	return plaintext;
}

//execution of the cipher for a single block
void feistel_block(unsigned char * left, unsigned char * right, unsigned char * round_key) 
{
	//buffer variable to temporarily store the left part of the block during the round execution
	unsigned char templeft[BLOCKSIZE/2];

	//execution of the cipher rounds on the block
	for (int i=0; i<NROUND; i++)
	{
		strncpy(templeft, left, BLOCKSIZE/2);

		strncpy(left, right, BLOCKSIZE/2);
		f(right, round_key);
		char_xor(right, templeft, right);
	}
	
	//final inversion of left and right parts of the block after the last round
	strncpy(templeft, left, BLOCKSIZE/2);
	strncpy(left, right, BLOCKSIZE/2);
	strncpy(right, templeft, BLOCKSIZE/2);

}

//placeholder for SP network
void f(unsigned char * right, unsigned char * key)
{
	unsigned char temp;
	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		right[i] = right[i] ^ key[i];
		if (i>0) right[i] = (right[i] | right[i-1]);
	}

	temp = right[0];
	right[0] = right[7];
	right[7] = temp;

	temp = right[1];
	right[1] =right[4];
	right[4] = temp;
	
	temp = right[2];
	right[2] = right[5];
	right[5] = temp;

	temp = right[3];
	right[3] = right[6];
	right[6] = temp;
}
