#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 10

int feistel_round(unsigned char * left, unsigned char * right, unsigned char * key);
void f(unsigned char * right, unsigned char * key);

typedef struct block {
    unsigned char left [BLOCKSIZE/2];
    unsigned char right [BLOCKSIZE/2];
    unsigned char round_key [KEYSIZE];
}block; 

unsigned char * feistel(unsigned char * data, unsigned char * key) 
{
	block b;
	for (int i=0; i<BLOCKSIZE/2; i++)
	{
		b.left[i] = data[i];
		b.right[i] = data[i+8];
	}
	strncpy(b.round_key, key, KEYSIZE);

	for (int i=0; i<NROUND; i++)
	{
		feistel_round(b.left, b.right, b.round_key);
	}
	
	//final inversion after the last round
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
