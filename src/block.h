void schedule_key(unsigned char round_keys[NROUND][KEYSIZE], unsigned char * key);
unsigned char * decrypt_blocks(unsigned char * data, unsigned long data_len, unsigned char * key, enum mode chosen);
unsigned char * encrypt_blocks(unsigned char * data, unsigned long data_len, unsigned char * key, enum mode chosen);
