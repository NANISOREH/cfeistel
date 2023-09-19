unsigned char * operate_ecb_mode(block * b, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * operate_ctr_mode(const block * b, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv, const int nchunk);
unsigned char * encrypt_cbc_mode(const block * b, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv, const int nchunk);
unsigned char * decrypt_cbc_mode(const block * b, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv, const int nchunk);
unsigned char * operate_ofb_mode(const block * b, const unsigned long data_len, const unsigned char round_keys[NROUND][KEYSIZE], const block iv, const int nchunk);
