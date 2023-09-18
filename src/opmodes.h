unsigned char * operate_ecb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * operate_ctr_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block iv);
unsigned char * encrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block iv);
unsigned char * decrypt_cbc_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block);
unsigned char * operate_ofb_mode(block * b, unsigned long bnum, unsigned char round_keys[NROUND][KEYSIZE], block iv);
