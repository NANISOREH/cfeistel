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
	strncpy(key, "defaultk", KEYSIZE);
	unsigned char * result;
	char * infile = "in";
	char * outfile = "out";

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
		printf("\nEnter a valid command! (enc/dec)");
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
			} 
			else
			{
				printf("\nEnter a non-empty key!");
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
			} 
			else
			{
				printf("\nEnter a non-empty filename!");
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
			} 
			else
			{
				printf("\nEnter a non-empty filename!");
				return -1;
			}
		}
		else if (strcmp(argv[i], "-ecb") == 0)
		{
			chosen = ecb;
		}
		else if (strcmp(argv[i], "-cbc") == 0) 
		{
			chosen = cbc;
		}
	}

	data = (unsigned char *)calloc (100000, sizeof(char));
	if (read_from_file(data, infile) == -1)
	{
		printf("\nInput file not found!");
		return -1;
	}

	result = feistel(data, key, chosen, to_do);
	free(data);
	print_to_file(result, outfile);

	return 0;
}
 
