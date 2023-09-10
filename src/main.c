#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "unistd.h" 
#include "fcntl.h"
#include "block.h"
#include "sys/time.h"
#include "omp.h"

enum mode chosen = DEFAULT_MODE;
enum operation to_do = DEFAULT_OP;
enum outmode output_mode = DEFAULT_OUT;
char * infile = "in";
char * outfile = "out";
unsigned char * key;
int saved_stdout;

//This variable notes the currently processing block relative to the whole file
//and not just relative the chunk that's currently in the buffer 
unsigned long total_file_size=0;
//This one notes the size of the current chunk of data, and it's set by the function that processed it
//so that it's always known in the main how much data do write out to file, regardless of wheter there's accounting blocks,
//prepended IV or anything else that might slightly alter the block count
unsigned long chunk_size=0;
unsigned long current_block=0; 
struct timeval start_time;

int command_selection(int argc, char * argv[]);

int command_selection(int argc, char * argv[])
{
	if (argc < 2) {
        fprintf(stderr, "Usage: %s enc|dec [-k key] [-i infile] [-o outfile] [-m mode]\n", argv[0]);
        return -1;
    }

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
		//num_blocks = sizeof(result)/BLOCKSIZE;
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
		//-i parameter, specified input file
		else if (strcmp(argv[i], "-i") == 0)
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
		//-o parameter, specified output file
		else if (strcmp(argv[i], "-o") == 0)
		{
			if (argv[i+1]!=NULL)
			{
				outfile = malloc (strlen(argv[i+1]) * sizeof(char));
				strcpy(outfile, argv[i+1]);
				i++;
				output_mode = specified;
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
		else
		{
			fprintf(stderr, "\nUnknown parameter '%s'\n", argv[i]);
			return -1;
		}
	}
}

int main(int argc, char * argv[]) 
{
	if (command_selection(argc, argv) == -1) return -1;

	unsigned char * data;
	unsigned int final_chunk_flag = 0;
	key = calloc (KEYSIZE, sizeof(char));
	strncpy(key, "secretkey", KEYSIZE);
	unsigned char * result;
	unsigned long num_blocks;
	//this one is the size of the current "pack" of blocks
	unsigned long size = 0;
	unsigned int chunk_num = 0;

	FILE * read_file;
	FILE * write_file;
	saved_stdout = dup(1);

	if (output_mode == replace) 
	{
		outfile = malloc ((strlen(infile) + 4) * sizeof(char));
		strcpy(outfile, infile);
		strncat(outfile, ".enc", 5);
	}

	//allocating space for the buffer, opening input and output files
	data = (unsigned char *)calloc (BUFSIZE + BLOCKSIZE, sizeof(unsigned char));
	read_file = fopen(infile, "rb");
	write_file = fopen(outfile, "wb"); //clears the file to avoid appending to an already written file
	write_file = freopen(outfile, "ab", write_file);

	if (read_file==NULL) 
	{
		exit_message(1, "Input file not found!");
		return -1;
	}

	//calculating the total file size and setting start time 
	fseek(read_file, 0, SEEK_END);
	total_file_size = ftell(read_file);
	rewind(read_file);
	gettimeofday(&start_time, NULL);

	#ifdef SEQ
    	omp_set_num_threads(1);
	#endif	

	//This loop will continue reading from read_file, processing data in chunks of BUFSIZE bytes and writing them to write_file,
	//until it reaches the last chunk of readable data. The standard way to understand when it's the last one is just checking if
	//fread read less than BUFSIZE bytes, but there are borderline cases that are checked in other ways.
	while (1)
	{	
		chunk_num++;
		//borderline case: if there's only an accounting block going over the BUFSIZE bounds, it's the last chunk.
		//We'll read an extra block in this iteration to make space for the accounting block in the current chunk.
		if (to_do == dec && check_last_block(read_file))
		{
			size = fread(data, sizeof(char), BUFSIZE + BLOCKSIZE, read_file);
			final_chunk_flag = 1;
		}
		else if (to_do == dec && chunk_num == 1 && chosen == cbc) //first chunk, we need to read one extra block (header)
		//only needed in decryption, for modes that require an IV/nonce
		{
			size = fread(data, sizeof(char), BUFSIZE + BLOCKSIZE, read_file);
		}
		else //normally reading BUFSIZE bytes
		{
			data = (unsigned char *)realloc(data, BUFSIZE * sizeof(unsigned char));
			size = fread(data, sizeof(char), BUFSIZE, read_file);
		}

		if (size < 0) //reading error
		{
			exit_message(1, "Input file not readable!");
			return -1;
		}
		else if (size < BUFSIZE) final_chunk_flag = 1;  //default case: if we read less than BUFSIZE bytes it's the last chunk of data
		else if (check_end_file(read_file)) final_chunk_flag = 1;	 //borderline case: buffer is full but there's EOF after this chunk

		//starting the correct operation and returning -1 in case there's an error
		if (to_do == enc) result = encrypt_blocks(data, size, key, chosen);
		else if (to_do == dec) result = decrypt_blocks(data, size, key, chosen);
		if (result == NULL) return -1;

		num_blocks = chunk_size/BLOCKSIZE;

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
				exit_message(1, "Wrong decryption key used!");
				remove(outfile);
				return -1;
			}
			fwrite(result, size, 1, write_file); 
		}
		else //in any other case we're using the number of blocks calculated before to determine how much text to write
		{
			fwrite(result,num_blocks * BLOCKSIZE, 1, write_file);
		}

		if (final_chunk_flag == 1) //it was the last chunk of data, we're done, closing files and printing some stats
		{
			fclose(read_file);
			fclose(write_file);
			if (output_mode == replace) 
			{
				remove(infile);
				rename(outfile, infile);
			}			
			struct timeval current_time;
			gettimeofday(&current_time, NULL);
			char speed[100];
			char time[100];
			char filesize[100];
			double time_diff = timeval_diff_seconds(start_time, current_time);
			snprintf(speed, sizeof(speed), "Avg processing speed: %.2f MB/s", estimate_speed(current_time));
			snprintf(time, sizeof(time), "Time elapsed: %.2f s", time_diff);
			snprintf(filesize, sizeof(filesize), "\nTotal file size: %.2f MB", (float)total_file_size / (1024.0 * 1024.0));
			exit_message(4, "Operation complete!\n", filesize, speed, time);

			break;
		}

		//zeroing data for the processed chunk from memory after writing it to file so that it cannot be dumped from memory
		memset(data, 0, size);
		memset(result, 0, num_blocks * BLOCKSIZE);
		
		free(result);
	}

	return 0;
}
 
