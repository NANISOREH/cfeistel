void operate_ecb_mode(unsigned char * result, block * b, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE]);
void operate_ctr_mode(unsigned char * result, block * b, const unsigned long data_len, const unsigned char round_keys[NROUND][KEYSIZE], const block iv);
void operate_ofb_mode (unsigned char * result, block * b, const unsigned long data_len, const unsigned char round_keys[NROUND][KEYSIZE], const block iv);
void encrypt_cbc_mode(unsigned char * ciphertext, block * plaintext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv);
void decrypt_cbc_mode(unsigned char * plaintext, block * ciphertext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv);
void encrypt_pcbc_mode(unsigned char * ciphertext, block * plaintext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv);
void decrypt_pcbc_mode(unsigned char * plaintext, block * ciphertext, const unsigned long bnum, const unsigned char round_keys[NROUND][KEYSIZE], const block iv);