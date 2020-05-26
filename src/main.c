#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"
#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 10

int main(int argc, char * argv[]) 
{
	unsigned char data[BLOCKSIZE];
	unsigned char key[KEYSIZE] = "defaultk";
	unsigned char * ciphertext;
	char * infile = "in";
	char * outfile = "out";

	for (int i=1; i<argc; i++)
	{
		//parametro -k da linea di comando, si legge una chiave
		if (strcmp(argv[i], "-k") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				//padding con 0 in caso sia inserita una chiave di meno di 8 caratteri (64 bit)
				if (strlen(argv[i+1]) < KEYSIZE)
				{
					for (int j = strlen(argv[i+1]); j<KEYSIZE; j++)
					{	
						argv[i+1][j] = '0';
					}
				}
				strncpy(key, argv[i+1], KEYSIZE);
			} 
			else
			{
				printf("\nEnter a non-empty key!");
				return -1;
			}
		}

		if (strcmp(argv[i], "-in") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				infile = malloc (strlen(argv[i+1]) * sizeof(char));
				strncpy(infile, argv[i+1], strlen(argv[i+1]));
			} 
			else
			{
				printf("\nEnter a non-empty filename!");
				return -1;
			}
		}

		if (strcmp(argv[i], "-out") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				outfile = malloc (strlen(argv[i+1]) * sizeof(char));
				strncpy(outfile, argv[i+1], strlen(argv[i+1]));
			} 
			else
			{
				printf("\nEnter a non-empty filename!");
				return -1;
			}
		}
	}

	read_from_file(data, infile);
	free(infile);

	if (strlen(data) < BLOCKSIZE)
	{
		for (int i = strlen(data); i<BLOCKSIZE; i++)
		{	
			data[i] = '0';
		}
	}

	ciphertext = feistel(data, key);
	print_to_file(ciphertext, outfile);

	return 0;
}
 
