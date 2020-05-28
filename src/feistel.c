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

    if (chosen == cbc_enc)
    	return encrypt_cbc_mode(b, bcount);
    else if (chosen == cbc_dec)
    	return decrypt_cbc_mode(b, bcount);

    return NULL;
}

//Executes the cipher in ECB mode; takes a block array and the number of blocks, returns processed data.
//it's a bit of a bad ECB, which is amazing, given how ECB is already conceptually bad.
//Thing is, you can't even take advantage of how multithreadable ECB is since i'm not handling concurrency at all
//and that would literally be the only upside of ECB. ¯\_(ツ)_/¯
/*unsigned char * operate_ecb_mode(block * b, int bnum)
{
	unsigned char * ciphertext;
	int bcount=0;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	for (int i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		feistel_block(b[bcount].left, b[bcount].right, b[bcount].round_key);
		
		for (int j=0; j<BLOCKSIZE; j++)	ciphertext[i+j] = b[bcount].left[j];
		bcount++;
	}

	return ciphertext;
}*/

//Executes encryption in CBC mode; takes a block array and the number of blocks, returns processed data.
unsigned char * encrypt_cbc_mode(block * b, int bnum)
{
	unsigned char * ciphertext;
	int bcount=0;
	ciphertext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));

	//prev_ciphertext will start off with the initialization vector, later it will be used in every iteration x 
	//to store the ciphertext of block x, needed to encrypt the block x+1
	block prev_ciphertext;
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		prev_ciphertext.left[i] = 128 + i;
		prev_ciphertext.right[i] = 138 + i;
	}

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	for (int i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{
		//XORing the current block x with the ciphertext of the block x-1
		half_block_xor(b[bcount].left, b[bcount].left, prev_ciphertext.left);
		half_block_xor(b[bcount].right, b[bcount].right, prev_ciphertext.right);
		
		//executing the encryption on block x and saving the result in prev_ciphertext; it will be used in the next iteration
		feistel_block(b[bcount].left, b[bcount].right, b[bcount].round_key);
		memcpy(&prev_ciphertext, &b[bcount], sizeof(block));
		
		//storing the ciphered block in the ciphertext variable
		for (int j=0; j<BLOCKSIZE; j++)	ciphertext[i+j] = b[bcount].left[j];
		bcount++;
	}

	return ciphertext;
}

//Executes decryption in CBC mode; takes a block array and the number of blocks, returns processed data.
unsigned char * decrypt_cbc_mode(block * b, int bnum)
{
	int bcount=0;
	unsigned char * plaintext;
	plaintext = calloc(BLOCKSIZE * bnum, sizeof(unsigned char));

	//making a copy of the whole ciphertext: for cbc decryption you need for each block the ciphertext of the
	//previous one. Since I'm operating the feistel algorithm in-place I needed to store those in advance.
	//Later I'll find a more elegant way to do it (like a partial buffer with instead of a full-on copy).
	block blocks_copy[bnum * sizeof(block)];
	memcpy(blocks_copy, b, bnum * sizeof(block));

	//initialization vector
	block iv;
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		iv.left[i] = 128 + i;
		iv.right[i] = 138 + i;
	}

	//launching the feistel algorithm on every block, by making the index jump by increments of BLOCKSIZE
	for (int i=0; i<BLOCKSIZE * bnum; i+=BLOCKSIZE) 
	{

		if (i % BLOCKSIZE == 0 && bcount < bnum) 
		{
			//First thing, you run feistel on the block,...
			feistel_block(b[bcount].left, b[bcount].right, b[bcount].round_key);

			if (i == 0)		//...if it's the first block, you xor it with the IV...
			{
				half_block_xor(b[bcount].left, b[bcount].left, iv.left);
				half_block_xor(b[bcount].right, b[bcount].right, iv.right);
			}
			else	//...whereas for every other ciphered block x, you xor it with x-1 
			{
				half_block_xor(b[bcount].left, b[bcount].left, blocks_copy[bcount-1].left);
				half_block_xor(b[bcount].right, b[bcount].right, blocks_copy[bcount-1].right);
			}
			
			//storing the deciphered block in plaintext variable
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

	//execution of NROUND cipher rounds on the block
	for (int i=0; i<NROUND; i++)
	{
		strncpy(templeft, left, BLOCKSIZE/2);

		strncpy(left, right, BLOCKSIZE/2);
		sp_network(right, round_key);
		half_block_xor(right, templeft, right);
	}
	
	//final inversion of left and right parts of the block after the last round
	strncpy(templeft, left, BLOCKSIZE/2);
	strncpy(left, right, BLOCKSIZE/2);
	strncpy(right, templeft, BLOCKSIZE/2);

}

//"f" function of the feistel cipher. Contains a VERY basic SP network. 
void sp_network(unsigned char * data, unsigned char * key)
{
	unsigned char left_part;
	unsigned char right_part;

	for (int i = 0; i<BLOCKSIZE/2; i++)
	{
		//XORing the round key with the block data
		data[i] = data[i] ^ key[i];

		//Splitting the bytes into two parts of 4 bits and feeding them to the substitution box.
		//Would have been better to leave them in one piece and operate on a 8-bit S-box? Yes.
		//Do I have better ways to spend my time than writing a 256-entries lookup table? Also yes. Barely, but yes. 
		split_byte(&left_part, &right_part, data[i]);
		s_box(&right_part);
		s_box(&left_part);
		merge_byte(&data[i], left_part, right_part);
	}

//Permutations, or kind of. I'm just moving whole bytes around, it would be better to find a way to
//move single bits all across the block.
	unsigned char temp;
	temp = data[0];
	data[0] = data[7];
	data[7] = temp;
	temp = data[1];
	data[1] =data[4];
	data[4] = temp;
	temp = data[2];
	data[2] = data[5];
	data[5] = temp;
	temp = data[3];
	data[3] = data[6];
	data[6] = temp;
}

void s_box(unsigned char * byte)
{
	switch (*byte)
	{
		case 0:	*byte = 7;
		case 1: *byte = 3;
		case 2: *byte = 9;
		case 3: *byte = 11;
		case 4: *byte = 15;
		case 5:	*byte = 14;
		case 6: *byte = 4;
		case 7: *byte = 5;
		case 8:	*byte = 1;
		case 9: *byte = 6;
		case 10: *byte = 8;
		case 11: *byte = 2;
		case 12: *byte = 10;
		case 13: *byte = 12;
		case 14: *byte = 0;
		case 15: *byte = 13;
	}

}
