//This module contains functions that manage the block data flow and the key scheduling, 

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "opmodes.h"
#include "omp.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"

//Schedules the round keys by compressing (or expanding, if smaller) the input key into and 8 byte master key  
//and then using it to derive one subkey for every round of the Feistel cipher
void schedule_key(unsigned char round_keys[NROUND][KEYSIZE], const char * key, const unsigned char * salt)
{
	unsigned char left_part;
	unsigned char right_part;
	unsigned char * master_key = malloc(KEYSIZE * sizeof(unsigned char));

    // Use PBKDF2 to derive a key
    int ret = PKCS5_PBKDF2_HMAC
	(
        key,
        strlen(key),
		salt,
        BLOCKSIZE,
        1000,
        EVP_sha256(), 
        KEYSIZE,
        master_key
    );


	memcpy(round_keys[0], master_key, KEYSIZE);

	for (int j = 0; j<NROUND; j++)
	{
		for (int i = 0; i<KEYSIZE; i++) 
		{			
			master_key[i] = (master_key[i] + 30 - i) % 256;	
			split_byte(&left_part, &right_part, master_key[i]);
			merge_byte(&master_key[i], right_part, left_part);
		}
		p_box(master_key);
		
		//the altered key generated in the iteration j is saved as round key number j,
		//the final result is an extended key stored in the round_keys matrix
		memcpy(round_keys[j], master_key, KEYSIZE);
	}

	free(master_key);
}

//Receives and organizes input data, takes the length of the chunk (as a pointer), the number of the current chunk, the input key,
//the header block array and the chosen operation mode enum value. 
//Returns the result of the encryption as a pointer to unsigned char, or NULL if an error is encountered.
//In case it has to add padding and/or an accounting block, it uses the chunk_size pointer to update the chunk size
void encrypt_blocks(unsigned char * result, unsigned char * data, const unsigned long chunk_size, int nchunk, const char * key, const block header[2], enum mode chosen)
{	
	char buffer[BLOCKSIZE];
	unsigned char round_keys[NROUND][KEYSIZE];
	unsigned long i=0;
	unsigned long bcount=0;

	//scheduling the round keys starting from the master key given
	schedule_key(round_keys, key, (unsigned char *)&header[0]);	//see the function schedule_key for info

   	//if the size of the last chunk is not multiple of the block size,
	//remainder will be the number of leftover bytes that will go into the padded block
	unsigned int remainder = chunk_size % BLOCKSIZE;

	//Figuring how much space we need for the blocks.
	//We only need extra blocks if we're at the last chunk of input data, because only in that case we have to append the data size and eventually add padding.
	//We understand that it's the last chunk when there's less data than the input buffer can contain.
	if (chunk_size == BUFSIZE)	//full buffer worth of data means it's not the last chunk of data, so we won't need to add extra blocks
		bcount = (chunk_size * sizeof(char)) / BLOCKSIZE;	
	else if (chunk_size < BUFSIZE && remainder == 0)		//last block: data size is multiple of the blocksize, we need an extra block
		bcount = ((chunk_size * sizeof(char)) / BLOCKSIZE) + 1;
	else if (chunk_size < BUFSIZE && remainder > 0)		//last block: data size is not multiple of the blocksize, we need two extra blocks
		bcount = ((chunk_size * sizeof(char)) / BLOCKSIZE) + 2;
	
	//Reallocating the data pointer as a block pointer with the new size
	block * b = (block *) data;

    //Padding shenanigans: they apply only if it's the last chunk of data read and we're not using a stream-like cipher.
    //It's a pretty naive padding scheme, but it works on any mode of operation so it simplifies coding.
    //I just 0-pad the last block if data length is not multiple of blocksize and use a size accounting block
    //to know how much of the last block is 0-padding to properly decrypt.
    if (chunk_size<BUFSIZE && is_stream_mode(chosen) == false)	
    {	
	    if (remainder>0)	//forming the last padded block, if there's leftover data
	    {
	    	for (int z=0; z<BLOCKSIZE; z++)	
	    	{
	    		if (z < remainder)	//there's still leftover data
	    			buffer[z] = data[((bcount-2) * BLOCKSIZE) + z];
	    		else	//no more leftover data, proceed with the padding
	    			buffer[z] = '0';
	    	}

			for (int y=0; y<BLOCKSIZE/2; y++)	//copying the buffered data on the padded block
			{
				b[bcount - 2].left[y] = buffer[y];
				b[bcount - 2].right[y] = buffer[y+8];
			}
	    }

	    //appending a final block to store the real(unpadded) size of the encrypted data
		block last_block;
		snprintf((char *)&last_block, BLOCKSIZE, "%lu", chunk_size);
	    int flag = 0;
	   	memcpy(&b[bcount-1], &last_block, sizeof(block));
	   	for (int i=0; i<BLOCKSIZE; i++)
	   	{
	   		if (flag == 1)
	   			b[bcount-1].left[i]='#';
	   		
	   		if (flag==0 && b[bcount-1].left[i] == '\0')
	   			flag = 1;
	   	}
	}

	switch (chosen) 
	{
        case cbc:
            encrypt_cbc_mode(result, b, bcount, round_keys, header[1]);
            break;
        case cfb:
            encrypt_cfb_mode(result, b, chunk_size, round_keys, header[1]);
            break;
        case pcbc:
            encrypt_pcbc_mode(result, b, bcount, round_keys, header[1]);
            break;
        case ecb:
            operate_ecb_mode(result, b, bcount, round_keys);
            break;
        case ctr:
            operate_ctr_mode(result, b, chunk_size, round_keys, header[1]);
            break;
        case ofb:
            operate_ofb_mode(result, b, chunk_size, round_keys, header[1]);
            break;
        default:
            return;
            break;
    }
}

//Receives and organizes input data, takes the length of the chunk, the number of the current chunk, the input key,
//the header block array and the chosen operation mode enum value. 
//Returns the result of the decryption as a pointer to unsigned char, or NULL if an error is encountered.
void decrypt_blocks(unsigned char * result, unsigned char * data, unsigned long data_len, int nchunk, const char * key, const block header[2], enum mode chosen)
{
	unsigned char buffer[BLOCKSIZE];
	unsigned char round_keys[NROUND][KEYSIZE];
	unsigned char temp[NROUND][KEYSIZE];
	unsigned long i=0;
	unsigned long bcount=0;

	//scheduling the round keys starting from the master key given
	schedule_key(round_keys, key, (unsigned char *)&header[0]);	//see the function schedule_key for info
	if (is_stream_mode(chosen) == false && chosen != cfb) //round keys sequence has to be inverted for decryption, except for stream-like modes
	{
		memcpy(temp, round_keys, NROUND * KEYSIZE);
		int j=NROUND-1;

		for (int i=0; i<NROUND; i++)
		{
			memcpy(round_keys[i], temp[j], NROUND);
			j--;
		}
	}

	bcount = (data_len * sizeof(char)) / BLOCKSIZE;

	switch (chosen) 
	{
        case cbc:
            decrypt_cbc_mode(result, (block *)data, bcount, round_keys, header[1]);
            break;
        case cfb:
            decrypt_cfb_mode(result, (block *)data, data_len, round_keys, header[1]);
            break;
        case pcbc:
            decrypt_pcbc_mode(result, (block *)data, bcount, round_keys, header[1]);
            break;
        case ecb:
            operate_ecb_mode(result, (block *) data, bcount, round_keys);
            break;
        case ctr:
            operate_ctr_mode(result, (block *)data, data_len, round_keys, header[1]);
            break;
        case ofb:
            operate_ofb_mode(result, (block *)data, data_len, round_keys, header[1]);
            break;
        default:
            return;
            break;
    }
}

