unsigned char * operate_ecb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * operate_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * decrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
int create_prepend_iv(block * iv, unsigned char * ciphertext, unsigned char round_keys[NROUND][KEYSIZE]);
int create_nonce(unsigned char nonce[KEYSIZE], unsigned char round_keys[NROUND][KEYSIZE]);