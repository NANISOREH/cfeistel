unsigned char * decrypt_blocks(unsigned char * data, unsigned long data_len, char * key, enum mode chosen);
unsigned char * encrypt_blocks(unsigned char * data, unsigned long data_len, char * key, enum mode chosen);
void schedule_key(unsigned char round_keys[NROUND][KEYSIZE], const char * key);