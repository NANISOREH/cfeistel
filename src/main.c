#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "utils.h"
#include "feistel.h"
#include "unistd.h" 
#include "fcntl.h" 

int main(int argc, char * argv[]) 
{
	enum mode chosen = DEFAULT_MODE;
	enum operation to_do = DEFAULT_OP;

	unsigned char * data;
	unsigned char * key;
	unsigned int final_chunk_flag = 0;
	key = calloc (KEYSIZE, sizeof(char));
	strncpy(key, "secretkey", KEYSIZE);
	unsigned char * result;
	unsigned long num_blocks;
	unsigned long size = 0;

	FILE * read_file;
	FILE * write_file;
	int saved_stdout = dup(1);
	dup2(open("/dev/null", O_WRONLY | O_APPEND), 1);
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
		fprintf(stderr, "\nEnter a valid command! (enc/dec)\n\n");
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
				fprintf(stderr, "\nEnter a non-empty key\n");
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
				fprintf(stderr, "\nEnter a non-empty filename\n");
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
				fprintf(stderr, "\nEnter a non-empty filename\n");
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
					fprintf(stderr, "\nEnter a valid mode of operation (ecb/cbc/ctr)\n");
					return -1;
				}
			} 
			else
			{
				fprintf(stderr, "\nEnter a non-empty filename!\n");
				return -1;
			}
		}
		//-v parameter, logging enabled
		else if (strcmp(argv[i], "-v") == 0)
		{
			dup2(saved_stdout, 1);
		}
		else
		{
			fprintf(stderr, "\nUnknown parameter '%s'\n", argv[i]);
			return -1;
		}
	}

	//allocating space for the buffer, opening input and output files
	data = (unsigned char *)calloc (BUFSIZE, sizeof(unsigned char));
	read_file = fopen(infile, "rb");
	write_file = fopen(outfile, "wb"); //clears the file to avoid appending to an already written file
	write_file = freopen(outfile, "ab", write_file);

	//This loop will continue reading from read_file, processing data in chunks of BUFSIZE bytes and writing them to write_file,
	//until it reaches the last chunk of readable data. The standard way to understand when it's the last one is just checking if
	//fread read less than BUFSIZE bytes, but there are borderline cases that are checked in other ways.
	while (1)
	{
		//checking for errors and reading the data, obtaining the size of the data read
		if (read_file==NULL) 
		{
			fprintf(stderr, "\nInput file not found!\n");
			return -1;
		}
		
		//borderline case: if there's only an accounting block going over the BUFSIZE bounds, it's the last chunk.
		//We'll read an extra block in this iteration to make space for the accounting block in the current chunk.
		if (to_do == dec && check_last_block(read_file))
		{
			size = fread(data, sizeof(char), BUFSIZE + BLOCKSIZE, read_file);
			final_chunk_flag = 1;
		}
		else //normally reading BUFSIZE bytes
		{
			size = fread(data, sizeof(char), BUFSIZE, read_file);
		}

		if (size < 0) //reading error
		{
			fprintf(stderr, "\nInput file not readable!\n");
			return -1;
		}
		else if (size < BUFSIZE) final_chunk_flag = 1;  //default case: if we read less than BUFSIZE bytes it's the last chunk of data
		else if (check_end_file(read_file)) final_chunk_flag = 1;	 //borderline case: buffer is full but there's EOF after this chunk
		
		//figuring out the number of blocks to write to file
		num_blocks = size/BLOCKSIZE;
		//In case it's an encryption and we're at the last chunk of data we have to add the extra blocks
		if (final_chunk_flag == 1 && to_do == enc)
		{
			if (size % BLOCKSIZE == 0) //multiple of blocksize, the ciphertext will need one extra block (only the size accounting block)
				num_blocks++;
			else //not multiple of blocksize, the ciphertext will need two extra blocks (0-padded block and size accounting block)
				num_blocks+=2;
		}

		//starting the correct operation and returning -1 in case there's an error
		if (to_do == enc) result = feistel_encrypt(data, size, key, chosen);
		else if (to_do == dec) result = feistel_decrypt(data, size, key, chosen);
		if (result == NULL) return -1;

		//In case we're decrypting the last chunk we use the size written in the last block (returned by remove_padding) to determine how much text to write,
		//and if there's no size written in the last block, it means that the specified decryption key was invalid.
		if (to_do == dec && final_chunk_flag == 1) 
		{ 
			size = remove_padding(result, num_blocks);
			
			//if the last chunk only contains an accounting block saying the chunk has 0 bytes, it means that the last chunk was
			//completely full and feistel_decrypt didn't detect it as "last chunk". In this case we can just use BUFSIZE as size.
			//It works, but I might want to find a less hacky solution to this issue.
			if (size == 0) 
			{
				size = BUFSIZE;
			}
			else if (size == -1) //no accounting block found in the last chunk, invalid key
			{
				fprintf(stderr, "\nWrong decryption key used!\n");
				return -1;
			}
			fwrite(result, size, 1, write_file); 
		}
		else //in any other case we're using the number of blocks calculated before to determine how much text to write
		{
			fwrite(result,num_blocks * BLOCKSIZE, 1, write_file); 
		}

		free(result);

		if (final_chunk_flag == 1) //it was the last chunk of data, we're done
		{
			fclose(read_file);
			fclose(write_file);
			break;
		}
	}

	return 0;
}
 
