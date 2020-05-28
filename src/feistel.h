#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 100
#define DEFAULT_MODE cbc_enc

enum mode{cbc_enc, cbc_dec}; 

//this structure represents the state of a block throught the rounds
typedef struct block {
    unsigned char left [BLOCKSIZE/2];
    unsigned char right [BLOCKSIZE/2];
    unsigned char round_key [KEYSIZE];
}block;

void sp_network(unsigned char * data, unsigned char * key); 
void s_box(unsigned char * byte);
void feistel_block(unsigned char * left, unsigned char * right, unsigned char * round_key);
unsigned char * feistel(unsigned char * data, unsigned char * key, enum mode chosen);
unsigned char * encrypt_cbc_mode(block * b, int bnum);
unsigned char * decrypt_cbc_mode(block * b, int bnum);