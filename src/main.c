#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#include "common.h"
#include "utils.h"
#include "feistel.h"
#include "unistd.h" 
#include "fcntl.h"
#include "block.h"
#include "sys/time.h"
#include "omp.h"
#include "getopt.h"

#include <bits/getopt_core.h>

enum mode chosen = DEFAULT_MODE;
enum operation to_do = DEFAULT_OP;
enum outmode output_mode = DEFAULT_OUT;
char * infile = "in";
char * outfile = "out";
unsigned char * key;
int saved_stdout;

//This variable stores the currently processing block relative to the whole file
//and not just relative the chunk that's currently in the buffer 
unsigned long total_file_size=0;
//This one stores the size of the current chunk of data, and it's set by the function that processed it
//so that it's always known in the main how much data do write out to file, regardless of wheter there's accounting blocks,
//prepended IV or anything else that might slightly alter the block count
unsigned long chunk_size=0;
unsigned long current_block=0; 
//nchunk will contain the number of chunks that have been processed
int nchunk=0;
struct timeval start_time;

int command_selection(int argc, char * argv[]);

int main(int argc, char * argv[]) 
{
	unsigned char * data;
	unsigned int final_chunk_flag = 0;
	key = calloc (KEYSIZE, sizeof(char));
	memcpy(key, "secretkey", KEYSIZE);
	unsigned char * result;
	unsigned long num_blocks;
	//This flag will signal the present of a final chunk that's only formed by the accounting block for the previous chunk
	//(the last one with actual data)
	bool acc_only_chunk = false;

	if (command_selection(argc, argv) == -1) return -1;

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
	//fread read less than BUFSIZE bytes
	while (1)
	{			
		if (to_do == dec && nchunk == 0 && chosen != ecb) //first chunk, we need to read one extra block (header)
		//only needed in decryption, for modes that require an IV/nonce
		{
			chunk_size = fread(data, sizeof(char), BUFSIZE + BLOCKSIZE, read_file);
		}
		else //normally reading BUFSIZE bytes
		{
			data = (unsigned char *)realloc(data, BUFSIZE * sizeof(unsigned char));
			chunk_size = fread(data, sizeof(char), BUFSIZE, read_file);
		}
		
		//If we read exactly BLOCKSIZE bytes, then the current chunk only contains the accounting block for the previous one
		//This only occurs when the actual data size falls within BLOCKSIZE bytes of a BUFSIZE multiple
		if (nchunk > 0 && chunk_size == BLOCKSIZE) acc_only_chunk = true;

		if (chunk_size < 0) //reading error
		{
			exit_message(1, "Input file not readable!");
			return -1;
		}
		else if (chunk_size < BUFSIZE) final_chunk_flag = 1;  //default case: if we read less than BUFSIZE bytes it's the last chunk of data
		else if (check_end_file(read_file)) final_chunk_flag = 1;	 //borderline case: buffer is full but there's EOF after this chunk

		//starting the correct operation and returning -1 in case there's an error
		if (to_do == enc) result = encrypt_blocks(data, chunk_size, key, chosen);
		else if (to_do == dec) result = decrypt_blocks(data, chunk_size, key, chosen);
		if (result == NULL) return -1;

		//incrementing the number of processed chunks
		nchunk++;
		//padding has not been applied yet in encryption or removed in decryption
		//so BLOCKSIZE should be a perfect divisor of chunk_size
		num_blocks = chunk_size/BLOCKSIZE;

		//In case we're decrypting the last chunk we use the size written in the last block (returned by remove_padding) to determine how much text to write,
		//and if there's no size written in the last block, it means that the specified decryption key was invalid.
		if (to_do == dec && final_chunk_flag == 1) 
		{ 
			//Removing padding from this chunk
			chunk_size = remove_padding(result, num_blocks, chosen, total_file_size);

			//if the last chunk only contains an accounting block saying the chunk has 0 bytes, it means that the last chunk was
			//completely full and feistel_decrypt didn't detect it as "last chunk". In this case we can just use BUFSIZE as size.
			//In the same way, if chunk_size was set to -1 by remove_padding it means there was no accounting block, and that means
			//that the input file's size was a perfect multiple of BUFSIZE
			if (chunk_size == 0 || chunk_size == -1) chunk_size = BUFSIZE;

			fwrite(result, chunk_size, 1, write_file); 
		}
		else //in any other case we're using the number of blocks calculated before to determine how much text to write
		{
			fwrite(result,num_blocks * BLOCKSIZE, 1, write_file);
		}

		if (final_chunk_flag == 1) //it was the last chunk of data, we're done, closing files and printing some stats
		{
			//This is needed when we are processing a chunk that only contains an accounting block 
			//In this case we can't directly remove the padding using the chunk size, because the chunk size we have is 
			//relative to the previous block, so we have to do some maths and truncate the whole file at the correct point
			if (acc_only_chunk && to_do == dec)
			{
				fseek(write_file, 0, SEEK_SET);
				ftruncate(fileno(write_file), chunk_size + ((nchunk - 2) * BUFSIZE));
			}

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
			if (to_do == enc) exit_message(4, "Encryption complete!\n", filesize, speed, time);
			else exit_message(4, "Decryption complete!\n", filesize, speed, time);

			break;
		}

		//zeroing data for the processed chunk from memory after writing it to file so that it cannot be dumped from memory
		memset(data, 0, chunk_size);
		memset(result, 0, num_blocks * BLOCKSIZE);		
	}

	free(data);
	return 0;
}

int command_selection(int argc, char *argv[]) 
{
    int opt;

    // Define the options and their arguments
    static struct option long_options[] = 
	{
        {"key", required_argument, NULL, 'k'},
        {"infile", required_argument, NULL, 'i'},
        {"outfile", required_argument, NULL, 'o'},
        {"mode", required_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };

    while ((opt = getopt_long(argc, argv, "k:i:o:m:", long_options, NULL)) != -1) 
	{
        switch (opt) 
		{
            case 'k':
                memcpy(key, optarg, KEYSIZE);
                break;
            case 'i':
                infile = optarg;
                break;
            case 'o':
                outfile = optarg;
                output_mode = specified;
                break;
            case 'm':
                if (strcmp(optarg, "ecb") == 0)
                    chosen = ecb;
                else if (strcmp(optarg, "cbc") == 0)
                    chosen = cbc;
                else if (strcmp(optarg, "ctr") == 0)
                    chosen = ctr;
                else 
				{
                    fprintf(stderr, "\nEnter a valid mode of operation (ecb/cbc/ctr)\n");
                    fprintf(stderr, "Usage: %s <enc|dec> [-k key] [-i infile] [-o outfile] [-m mode]\n", argv[0]);
                    return -1;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s <enc|dec> [-k key] [-i infile] [-o outfile] [-m mode]\n", argv[0]);
                return -1;
        }
    }

    // Check if the operation (enc or dec) is provided as a positional argument
    if (optind < argc) 
	{
        if (strcmp(argv[optind], "enc") == 0)
            to_do = enc;
        else if (strcmp(argv[optind], "dec") == 0)
            to_do = dec;
        else {
            fprintf(stderr, "Invalid operation: %s\n", argv[optind]);
            return -1;
        }
    }

    return 0;
}
 
