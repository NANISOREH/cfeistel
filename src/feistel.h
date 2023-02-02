void sp_network(unsigned char * data, unsigned char * key); 
void s_box(unsigned char * byte, int side);
void p_box(unsigned char * data);
void process_block(unsigned char * left, unsigned char * right, unsigned char round_keys[NROUND][KEYSIZE]);
void schedule_key(unsigned char round_keys[NROUND][KEYSIZE], unsigned char * key);