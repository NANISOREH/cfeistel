#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"


/*//input data handling, starts execution of the cipher
unsigned char * feistel(unsigned char * data, unsigned char * key)
{
	printf("%s, %lu", data, strlen(data));

	if (key!=NULL && data!=NULL)
	{
		//key is too short, applying padding
		if (strlen(key) < KEYSIZE)
		{
			for (int j = strlen(key); j<KEYSIZE; j++)
			{	
				key[j] = '0';
			}
		}

		//block is too short, applying padding
		if (strlen(data) < BLOCKSIZE)
		{
			for (int i = strlen(data); i<BLOCKSIZE; i++)
			{	
				data[i] = '0';
			}
		}
	}
	else
	{
		printf ("Malformed block!");
		return NULL;
	}

	printf("\n%s, %lu", data, strlen(data));

	block b;

    for (int j=0; j<BLOCKSIZE/2; j++)
	{
		b.left[j] = data[j];
		b.right[j] = data[j+8];
	}
	strncpy(b.round_key, key, KEYSIZE);


	return feistel_block(b);
} */

//input data handling, starts execution of the cipher
unsigned char * feistel(unsigned char * data, unsigned char * key)
{
	int remainder = strlen(data) % BLOCKSIZE;
	unsigned char buffer[BLOCKSIZE];
	unsigned char * ciphertext;
	int i=0;
	int bcount;

	//allocating space for the blocks. 
	block * b;
	if (remainder == 0)		//data size is multiple of the blocksize
		b = malloc((strlen(data) / BLOCKSIZE) * sizeof(block));		
	else					//data size is not multiple of the blocksize
		b = malloc((strlen(data) / BLOCKSIZE + 1) * sizeof(block));	

	while (i < strlen(data))
    {
        buffer[i % BLOCKSIZE] = data[i];
        i++;

        if ((i+1) % BLOCKSIZE == 0)		//completed a block
        {
        	buffer[i % BLOCKSIZE] = data[i];
        	i++;
        	printf("buffer %s\n", buffer);
        	for (int j=0; j<BLOCKSIZE/2; j++)	//filling the block with the buffered data
			{
				b[bcount].left[j] = buffer[j];
				b[bcount].right[j] = buffer[j+8];
			}
			//for now, the round key is the same for every round
			//TODO: key scheduling/derivation
			strncpy(b[bcount].round_key, key, KEYSIZE);
			bcount++;
        }
    }

/*    if (remainder>0)	//forming the last 0-padded block, if there's leftover data
    {
    	for (int z=0; z<BLOCKSIZE; z++)
    	{
    		if (z <= remainder)
    			buffer[z] = data[(bcount * BLOCKSIZE) + z];
    		else
    			buffer[z] = '0';
    	}
		for (int y=0; y<BLOCKSIZE/2; y++)
		{
			b[bcount].left[y] = buffer[y];
			b[bcount].right[y] = buffer[y+8];
			strncpy(b[bcount].round_key, key, KEYSIZE);
		}
		bcount++;
    }*/

    ciphertext = malloc(BLOCKSIZE);
    ciphertext = feistel_block(b[0]);
    //TODO: calling for every block and concatenating results

    return ciphertext;
}


//execution of the cipher for a single block
unsigned char * feistel_block(block b) 
{
	for (int i=0; i<NROUND; i++)
	{
		feistel_round(b.left, b.right, b.round_key);
	}
	
	//final inversion of left and right parts of the block after the last round
	unsigned char templeft[KEYSIZE];
	strncpy(templeft, b.left, KEYSIZE);
	strncpy(b.left, b.right, KEYSIZE);
	strncpy(b.right, templeft, KEYSIZE);

	unsigned char * out;
	out = malloc(BLOCKSIZE);
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		out[i] = b.left[i];
		out[i+8] = b.right[i];
	}

	return out;
}

//execution of a single round of the cipher
int feistel_round(unsigned char * left, unsigned char * right, unsigned char * key)
{
	unsigned char templeft[KEYSIZE];
	strncpy(templeft, left, KEYSIZE);

	strncpy(left, right, KEYSIZE);
	f(right, key);
	char_xor(right, templeft, right);
}

//placeholder substitution box
void f(unsigned char * right, unsigned char * key)
{
	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		if (i % 2 == 0)
			right[i] = right[i] + key[i];
		else
			right[i] = right[i] - key[i];
	}
}
