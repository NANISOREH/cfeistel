#define BUFSIZE 1000000
void print_byte(char c);
int half_block_xor(unsigned char * result, unsigned char * first, unsigned char * second);
void print_to_file(unsigned char * out, char * filename, int num_blocks);
unsigned long remove_padding(unsigned char * result, int num_blocks);
int read_from_file(unsigned char * buffer, char * filename);
void split_byte(unsigned char * left_part, unsigned char * right_part, unsigned char whole);
void merge_byte(unsigned char * target, unsigned char left_part, unsigned char right_part);
void print_block(unsigned char * left, unsigned char * right);
void stringify_counter(unsigned char * string, int counter);
void swap_bit(unsigned char * first, unsigned char * second, unsigned int pos_first, unsigned int pos_second);
void str_safe_copy(unsigned char * dest, unsigned char * src, unsigned long size);
void str_safe_print(unsigned char * to_print, unsigned long size);
unsigned long str_safe_len(unsigned char * string);
