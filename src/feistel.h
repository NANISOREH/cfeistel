void sp_network(unsigned char * data, const unsigned char * key); 
void s_box(unsigned char * byte, int side);
void p_box(unsigned char * data);
void process_block(unsigned char * target, const unsigned char * left, const unsigned char * right, const unsigned char round_keys[NROUND][KEYSIZE]);