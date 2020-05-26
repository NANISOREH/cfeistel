#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"

int main(int argc, char * argv[]) 
{
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
				infile = malloc (strlen(argv[i+1]) * sizeof(char));
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
	}

	data = malloc (1000 * sizeof(char));
	if (read_from_file(data, infile) == -1)
	{
		printf("\nInput file not found!");
		return -1;
	}
	data = realloc(data, strlen(data) * sizeof(char));

	ciphertext = feistel(data, key);
	print_to_file(ciphertext, outfile);

	return 0;
}
 
