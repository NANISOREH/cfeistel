//This module contains functions that perform the cipher execution on a single block.
//In other words, the feistel cipher itself.

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"

//execution of the cipher for a single block
void process_block(unsigned char * left, unsigned char * right, unsigned char round_keys[NROUND][KEYSIZE]) 
{	
	//buffer variable to temporarily store the left part of the block during the round execution
	unsigned char templeft[BLOCKSIZE/2];

	for (int i=0; i<NROUND; i++)	//execution of NROUND cipher rounds on the block
	{
		memcpy(templeft, left, BLOCKSIZE/2);

		memcpy(left, right, BLOCKSIZE/2);	//the right half in a round becomes the left half in the next round
		sp_network(right, round_keys[i]);	//f(right)
		half_block_xor(right, templeft, right);	  //f(right) XOR left 
	}

	//final inversion of left and right parts of the block after the last round
	memcpy(templeft, left, BLOCKSIZE/2);
	memcpy(left, right, BLOCKSIZE/2);
	memcpy(right, templeft, BLOCKSIZE/2);
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

		//Splitting the bytes into two parts of 4 bits and feeding them to the substitution box,
		//then merging the result together.
		split_byte(&left_part, &right_part, data[i]);
		s_box(&right_part, 0);
		s_box(&left_part, 1);
		merge_byte(&data[i], left_part, right_part);
	}

	//feeding data to the permutation box, where bits will get swapped all around
	p_box(data);
}

//4-bit input -> 4-bit output substitution boxes.
//The side parameter differentiates between the two S-boxes: 
//0 is for the left side of the byte and 1 is for the right.
void s_box(unsigned char * byte, int side)
{
	if (side == 0)
	{	
		switch (*byte)
		{
			case 0:	*byte = 14; break;
			case 1: *byte = 2; break;
			case 2: *byte = 9; break;
			case 3: *byte = 11; break;
			case 4: *byte = 15; break;
			case 5:	*byte = 4; break;
			case 6: *byte = 4; break;
			case 7: *byte = 3; break;
			case 8: *byte = 5; break;
			case 9: *byte = 6; break;
			case 10: *byte = 11; break;
			case 11: *byte = 1; break;
			case 12: *byte = 10; break;
			case 13: *byte = 8; break;
			case 14: *byte = 12; break;
			case 15: *byte = 13; break;
		}
	} 
	else if (side == 1)
	{
		switch (*byte)
		{
			case 0:	*byte = 14; break;
			case 1: *byte = 2; break;
			case 2: *byte = 9; break;
			case 3: *byte = 0; break;
			case 4: *byte = 15; break;
			case 5:	*byte = 0; break;
			case 6: *byte = 7; break;
			case 7: *byte = 3; break;
			case 8: *byte = 5; break;
			case 9: *byte = 6; break;
			case 10: *byte = 7; break;
			case 11: *byte = 1; break;
			case 12: *byte = 10; break;
			case 13: *byte = 8; break;
			case 14: *byte = 12; break;
			case 15: *byte = 13; break;
		}
	}
}

//64-bit permutation box
void p_box(unsigned char data[BLOCKSIZE/2])
{
	swap_bit(&data[0], &data[7], 2, 4);
	swap_bit(&data[0], &data[7], 1, 6);
	swap_bit(&data[0], &data[7], 7, 5);
	swap_bit(&data[0], &data[7], 3, 7);
	swap_bit(&data[0], &data[7], 0, 1);
	swap_bit(&data[0], &data[7], 4, 0);
	swap_bit(&data[0], &data[7], 5, 3);
	swap_bit(&data[0], &data[7], 6, 2);

	swap_bit(&data[1], &data[4], 0, 7);
	swap_bit(&data[1], &data[4], 1, 6);
	swap_bit(&data[1], &data[4], 2, 5);
	swap_bit(&data[1], &data[4], 3, 4);
	swap_bit(&data[1], &data[4], 4, 3);
	swap_bit(&data[1], &data[4], 5, 2);
	swap_bit(&data[1], &data[4], 6, 1);
	swap_bit(&data[1], &data[4], 7, 0);

	swap_bit(&data[2], &data[5], 7, 4);
	swap_bit(&data[2], &data[5], 6, 6);
	swap_bit(&data[2], &data[5], 5, 5);
	swap_bit(&data[2], &data[5], 4, 7);
	swap_bit(&data[2], &data[5], 3, 1);
	swap_bit(&data[2], &data[5], 2, 0);
	swap_bit(&data[2], &data[5], 1, 3);
	swap_bit(&data[2], &data[5], 0, 2);

	swap_bit(&data[3], &data[6], 5, 4);
	swap_bit(&data[3], &data[6], 2, 6);
	swap_bit(&data[3], &data[6], 3, 5);
	swap_bit(&data[3], &data[6], 1, 7);
	swap_bit(&data[3], &data[6], 7, 1);
	swap_bit(&data[3], &data[6], 6, 0);
	swap_bit(&data[3], &data[6], 4, 3);
	swap_bit(&data[3], &data[6], 0, 2);
}
