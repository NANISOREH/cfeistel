#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"

int main(int argc, char * argv[]) 
{
	enum mode chosen = DEFAULT_MODE;

	unsigned char * data;
	unsigned char * key = "defaultk";
	unsigned char * ciphertext;
	char * infile = "in";
	char * outfile = "out";

	for (int i=1; i<argc; i++)
	{
		//-k parameter, specified key
		if (strcmp(argv[i], "-k") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				key = calloc (strlen(argv[i+1]), sizeof(char));
				strcpy(key, argv[i+1]);
			} 
			else
			{
				printf("\nEnter a non-empty key!");
				return -1;
			}
		}
		//-in parameter, specified input file
		if (strcmp(argv[i], "-in") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				infile = calloc (strlen(argv[i+1]), sizeof(char));
				strcpy(infile, argv[i+1]);
			} 
			else
			{
				printf("\nEnter a non-empty filename!");
				return -1;
			}
		}
		//-out parameter, specified output file
		if (strcmp(argv[i], "-out") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				outfile = malloc (strlen(argv[i+1]) * sizeof(char));
				strcpy(outfile, argv[i+1]);
			} 
			else
			{
				printf("\nEnter a non-empty filename!");
				return -1;
			}
		}
		if (strcmp(argv[i], "-mode") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				if (strcmp(argv[i+1], "ecb") == 0) chosen = ecb;
				else if (strcmp(argv[i+1], "cbc-enc") == 0) chosen = cbc_enc;
				else if (strcmp(argv[i+1], "cbc-dec") == 0) chosen = cbc_dec;
				else 
				{
					printf("\nEnter a valid mode!");
					return -1;
				}
			} 
			else
			{
				printf("\nEnter a valid mode!");
				return -1;
			}
		}
	}

	data = (unsigned char *)calloc (100000, sizeof(char));
	if (read_from_file(data, infile) == -1)
	{
		printf("\nInput file not found!");
		return -1;
	}

	ciphertext = feistel(data, key, chosen);
	free(data);
	print_to_file(ciphertext, outfile);

	return 0;
}
 
