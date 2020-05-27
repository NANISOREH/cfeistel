#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"

//input data handling, starts execution of the cipher
unsigned char * feistel(unsigned char * data, unsigned char * key)
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

    return operate_ecb_mode(b, bcount);
}

//executes the cipher in ECB mode; takes a block array and the number of blocks, returns processed data
unsigned char * operate_ecb_mode(block * b, int bnum)
{
	unsigned char * ciphertext;
	unsigned char done_block[BLOCKSIZE];
	int bcount=0;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));

	//launching the feistel algorithm on every block, storing the result in ciphertext
	for (int i=0; i<BLOCKSIZE * bnum; i++) 
	{
		if (i % BLOCKSIZE == 0 && bcount < bnum) 
		{
			feistel_block(done_block, b[bcount]);
			bcount++;
		}

		ciphertext[i] = done_block[i % BLOCKSIZE];
	}

	return ciphertext;
}


//execution of the cipher for a single block
void feistel_block(unsigned char * out, block b) 
{
	//buffer variable to temporarily store the left part of the block during the round execution
	unsigned char templeft[BLOCKSIZE/2];

	//execution of the cipher rounds on the block
	for (int i=0; i<NROUND; i++)
	{
		strncpy(templeft, b.left, BLOCKSIZE/2);

		strncpy(b.left, b.right, BLOCKSIZE/2);
		f(b.right, b.round_key);
		char_xor(b.right, templeft, b.right);
	}
	
	//final inversion of left and right parts of the block after the last round
	strncpy(templeft, b.left, BLOCKSIZE/2);
	strncpy(b.left, b.right, BLOCKSIZE/2);
	strncpy(b.right, templeft, BLOCKSIZE/2);

	//merging left and right part into an array to return the result of the execution
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		out[i] = b.left[i];
		out[i+8] = b.right[i];
	}
}

//placeholder substitution box
void f(unsigned char * right, unsigned char * key)
{
	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		right[i] = right[i] ^ key[i];
	}

	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		right[i] = (right[i] | 9) % 255;
		right[i] = (right[i] | 10) % 255;
	}
}
