#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 8
#define DEFAULT_MODE ecb

enum mode{cbc_enc, cbc_dec, ecb}; 

//this structure represents the state of a block throught the rounds
typedef struct block {
    unsigned char left [BLOCKSIZE/2];
    unsigned char right [BLOCKSIZE/2];
    unsigned char round_key [KEYSIZE];
}block;

void sp_network(unsigned char * data, unsigned char * key); 
void s_box(unsigned char * byte);
void feistel_block(unsigned char * left, unsigned char * right, unsigned char * round_key);
void schedule_key(unsigned char * key, int bcount);
unsigned char * feistel(unsigned char * data, unsigned char * key, enum mode chosen);
unsigned char * operate_ecb_mode(block * b, int bnum);
unsigned char * encrypt_cbc_mode(block * b, int bnum);
unsigned char * decrypt_cbc_mode(block * b, int bnum);