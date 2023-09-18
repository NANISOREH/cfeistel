//Debug/logging utils
void print_byte(char c);
void block_logging(unsigned char * b, const char* message, unsigned long bcount);
double timeval_diff_seconds(struct timeval start, struct timeval end);
long unsigned compute_checksum(const unsigned char *data, const long unsigned size);
void exit_message(int num_strings, ...);
void show_progress_data(struct timeval current_time);
double estimate_speed (struct timeval current_time);
void str_safe_print(unsigned char * to_print, unsigned long size);
//Maths utils
long unsigned derive_number_from_block(block * b);
void derive_block_from_number(long unsigned num, block *b);
int half_block_xor(unsigned char * result, const unsigned char * first, const unsigned char * second);
void split_byte(unsigned char * left_part, unsigned char * right_part, unsigned char whole);
void merge_byte(unsigned char * target, unsigned char left_part, unsigned char right_part);
void swap_bit(unsigned char * first, unsigned char * second, unsigned int pos_first, unsigned int pos_second);
long unsigned create_nonce(block * nonce);
void block_xor(block *result, const block *first, const block *second);
//Data flow utils
unsigned long remove_padding(unsigned char * result, unsigned long num_blocks, enum mode chosen, unsigned long total_file_size);
int check_end_file(FILE *stream);
int prepend_block(block * b, unsigned char * data);
bool is_stream_mode(enum mode chosen);