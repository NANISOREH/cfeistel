#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#include "common.h"
#include "utils.h"
#include "block.h"
#include "feistel.h"
#include "unistd.h" 
#include "fcntl.h"
#include "sys/time.h"
#include "omp.h"
#include "getopt.h"
#include <bits/getopt_core.h>

unsigned long total_file_size=0;
struct timeval start_time;

int command_selection(int argc, char *argv[], char * key, char * infile, char * outfile, enum mode chosen, enum operation to_do, enum outmode output_mode) ;

int main(int argc, char * argv[]) 
{
	//Variables that will be populated by user command selection
	enum mode chosen = DEFAULT_MODE;
	enum operation to_do = DEFAULT_OP;
	enum outmode output_mode = DEFAULT_OUT;
	char * infile = "in";
	char * outfile = "out";
	char * key = NULL;

	unsigned char * data;
	unsigned int final_chunk_flag = 0;
	unsigned char * result;
	unsigned long num_blocks;
	//nchunk will contain the number of chunks that have currently been processed
	int nchunk=0;
	//chunk_size stores the size of the current chunk of data, and it's set by the function that processed it
	//so that it's always known in the main how much data do write out to file, regardless of wheter there's accounting blocks,
	//or anything else that might slightly alter the block count
	unsigned long chunk_size=0;
	//This flag will signal a final chunk that's only formed by the accounting block for the previous chunk
	//(the last one with actual data)
	bool acc_only_chunk = false;
	//2 blocks header that will contain IV and key derivation salt 
	block header[2];
	
	FILE * read_file;
	FILE * write_file;
	int saved_stdout;
	saved_stdout = dup(1);

	#ifdef SEQ
		omp_set_num_threads(1);
	#endif	

	if (command_selection(argc, argv, key, infile, outfile, chosen, to_do, output_mode) == -1) return -1;

	//Key not received in input, we'll use "secretkey" as key
	if (key == NULL)
	{
		key = calloc (KEYSIZE+1, sizeof(char));
		strncpy(key, "secretkey", KEYSIZE);
	}

	if (output_mode == replace) //Sets up the output filename for replace mode:
	//at the end of the processing, the provided file will be removed and the new file will take its name
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

	if (to_do == enc) //We need to generate the header and prepend it to the ciphertext
	{
		create_nonce(&header[0]);
		create_nonce(&header[1]);
		fwrite(&header, BLOCKSIZE, 2, write_file);
	}
	else //We need to populate the header with the first two blocks of the ciphertext 
	{
		fread(&header[0], BLOCKSIZE, 1, read_file);
		fread(&header[1], BLOCKSIZE, 1, read_file);
	}

	//calculating the total file size and setting start time 
	fseek(read_file, 0, SEEK_END);
	total_file_size = ftell(read_file);
	rewind(read_file);
	if (to_do == dec) //In decryption, we have to ignore the first two blocks (header)
	{
		fseek(read_file, 2*BLOCKSIZE, SEEK_SET);
		total_file_size -= 2*BLOCKSIZE;
	}

	gettimeofday(&start_time, NULL);

	//This loop will continue reading from read_file, processing data in chunks of BUFSIZE bytes and writing them to write_file,
	//until it reaches the last chunk of readable data. The standard way to understand when it's the last one is just checking if
	//fread read less than BUFSIZE bytes
	while (1)
	{			
		//Trying to read BUFSIZE characters, saving the number of read characters in chunk_size
		data = (unsigned char *)realloc(data, BUFSIZE * sizeof(unsigned char));
		chunk_size = fread(data, sizeof(char), BUFSIZE, read_file);
		
		//If we read exactly BLOCKSIZE bytes, then the current chunk only contains the accounting block for the previous one
		//This only occurs when the actual data size falls within BLOCKSIZE bytes of a BUFSIZE multiple
		//This does not apply to stream-like modes like OFB, because those need no padding and no accounting.
		if (nchunk > 0 && chunk_size == BLOCKSIZE && is_stream_mode(chosen) == false) acc_only_chunk = true;

		if (chunk_size < 0) //reading error
		{
			exit_message(1, "Input file not readable!");
			return -1;
		}
		else if 
			(chunk_size < BUFSIZE) final_chunk_flag = 1;  //default case: if we read less than BUFSIZE bytes it's the last chunk of data
		else if 
			(check_end_file(read_file)) final_chunk_flag = 1;	 //borderline case: buffer is full but there's EOF after this chunk

		//starting the correct operation and returning -1 in case there's an error
		if (to_do == enc) 
			result = encrypt_blocks(data, &chunk_size, nchunk, key, header, chosen);
		else if (to_do == dec) 
			result = decrypt_blocks(data, chunk_size, nchunk, key, header, chosen);
		
		if (result == NULL)
		{
			fclose(write_file);
			fclose(read_file);
			free(data);
			return -1;
		}

		//incrementing the number of processed chunks
		nchunk++;

		//In case we're decrypting the last chunk we use the size written in the last block (returned by remove_padding) to determine how much text to write,
		//and if there's no size written in the last block, it means that the specified decryption key was invalid.
		//This does not apply to stream-like modes like OFB, because those need no padding and no accounting.
		if (to_do == dec && final_chunk_flag == 1 && is_stream_mode(chosen) == false)
		{ 
			//padding has not been applied yet in encryption or removed in decryption
			//so BLOCKSIZE should be a perfect divisor of chunk_size
			num_blocks = chunk_size/BLOCKSIZE;

			//Removing padding from this chunk
			chunk_size = remove_padding(result, num_blocks, chosen, total_file_size);

			//if the last chunk only contains an accounting block saying the chunk has 0 bytes, it means that the last chunk was
			//completely full and feistel_decrypt didn't detect it as "last chunk". In this case we can just use BUFSIZE as size.
			//In the same way, if chunk_size was set to -1 by remove_padding it means there was no accounting block, and that means
			//that the input file's size was a perfect multiple of BUFSIZE
			if (chunk_size == 0 || chunk_size == -1) chunk_size = BUFSIZE;
		}

		fwrite(result, chunk_size, 1, write_file); 

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
			snprintf(speed, sizeof(speed), "Avg processing speed: %.2f MB/s", estimate_speed(current_time, start_time, total_file_size/BLOCKSIZE));
			snprintf(time, sizeof(time), "Time elapsed: %.2f s", time_diff);
			snprintf(filesize, sizeof(filesize), "\nTotal file size: %.2f MB", (float)total_file_size / (1000.0 * 1000.0));
			if (to_do == enc) exit_message(4, "Encryption complete!\n", filesize, speed, time);
			else exit_message(4, "Decryption complete!\n", filesize, speed, time);

			break;
		}

		//zeroing data for the processed chunk from memory after writing it to file so that it cannot be dumped from memory
		memset(data, 0, chunk_size);
		memset(result, 0, num_blocks * BLOCKSIZE);		
	}

	free(result);
	free(data);
	return 0;
}

int command_selection(int argc, char *argv[], char * key, char * infile, char * outfile, enum mode chosen, enum operation to_do, enum outmode output_mode) 
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
				key = malloc((strlen(optarg)+1) * sizeof(char));
                strcpy(key, optarg);
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
				else if (strcmp(optarg, "ofb") == 0)
                    chosen = ofb;
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
 
