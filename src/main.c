#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"

int main(int argc, char * argv[]) 
{
	enum mode chosen = DEFAULT_MODE;
	enum operation to_do = DEFAULT_OP;

	unsigned char * data;
	unsigned char * key;
	key = calloc (KEYSIZE, sizeof(char));
	strncpy(key, "12345678", KEYSIZE);
	unsigned char * result;
	int num_blocks;
	char * infile = "in";
	char * outfile = "out";

	//command choice, enc or dec
	if (argv[1]!= NULL && strcmp(argv[1], "enc") == 0)
	{
		to_do = enc;
	}
	else if (argv[1]!= NULL && strcmp(argv[1], "dec") == 0)
	{
		to_do = dec;
	}
	else
	{
		printf("\nEnter a valid command! (enc/dec)\n\n");
		return -1;
	}	

	for (int i=2; i<argc; i++)
	{	
		//-k parameter, specified key
		if (strcmp(argv[i], "-k") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				key = calloc (KEYSIZE, sizeof(char));
				strncpy(key, argv[i+1], KEYSIZE);
				i++;
			} 
			else
			{
				printf("\nEnter a non-empty key\n");
				return -1;
			}
		}
		//-in parameter, specified input file
		else if (strcmp(argv[i], "-in") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				infile = calloc (strlen(argv[i+1]), sizeof(char));
				strcpy(infile, argv[i+1]);
				i++;
			} 
			else
			{
				printf("\nEnter a non-empty filename\n");
				return -1;
			}
		}
		//-out parameter, specified output file
		else if (strcmp(argv[i], "-out") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				outfile = malloc (strlen(argv[i+1]) * sizeof(char));
				strcpy(outfile, argv[i+1]);
				i++;
			} 
			else
			{
				printf("\nEnter a non-empty filename\n");
				return -1;
			}
		}
		//-m parameter, specified mode of operation
		else if (strcmp(argv[i], "-m") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				if (strcmp(argv[i+1], "ecb") == 0)
				{
					chosen = ecb;
					i++;
				}
				else if (strcmp(argv[i+1], "cbc") == 0) 
				{
					chosen = cbc;
					i++;
				}
				else if (strcmp(argv[i+1], "ctr") == 0) 
				{
					chosen = ctr;
					i++;
				}
				else
				{
					printf("\nEnter a valid mode of operation (ecb/cbc/ctr)\n");
					return -1;
				}
			} 
			else
			{
				printf("\nEnter a non-empty filename!\n");
				return -1;
			}
		}
		else
		{
			printf("\nUnknown parameter '%s'\n", argv[i]);
			return -1;
		}
	}

	data = (unsigned char *)calloc (BUFSIZE, sizeof(char));
	if (read_from_file(data, infile) == -1)
	{
		printf("\nInput file not found!\n");
		return -1;
	}

	//figuring out the number of blocks to write in case it's an encryption
	num_blocks = str_safe_len(data)/BLOCKSIZE;
	if (to_do == enc && str_safe_len(data) % BLOCKSIZE == 0)	
		num_blocks++;
	else if(to_do == enc)
		num_blocks+=2;

	//starting the correct operation
	if (to_do == enc) result = feistel_encrypt(data, key, chosen);
	else if (to_do == dec) result = feistel_decrypt(data, key, chosen);
	free(data);

	//figuring out the final size of the output and printing to file 
	unsigned long size;
	if (to_do == dec) //using the size written in the last block (returned by remove_padding) to determine how much text to write
	{ 
		size = remove_padding(result);
		print_to_file(result, outfile, size);
	}
	else //using the number of blocks calculated before to determine how much text to write
		print_to_file(result, outfile, num_blocks * BLOCKSIZE);

	return 0;
}
 
