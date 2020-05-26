#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 10	

//this structure represents the state of a block throught the rounds
typedef struct block {
    unsigned char left [BLOCKSIZE/2];
    unsigned char right [BLOCKSIZE/2];
    unsigned char round_key [KEYSIZE];
}block;

int feistel_round(unsigned char * left, unsigned char * right, unsigned char * key);
void f(unsigned char * right, unsigned char * key); 
unsigned char * feistel_block(block b);
unsigned char * feistel(unsigned char * data, unsigned char * key);