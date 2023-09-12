unsigned char * operate_ecb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * encrypt_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * decrypt_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * decrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);