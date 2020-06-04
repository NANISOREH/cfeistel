#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 10
#define DEFAULT_MODE ecb
#define DEFAULT_OP enc

enum operation{enc, dec};
enum mode{cbc, ecb, ctr}; 

//this structure represents the state of a block throught the rounds
typedef struct block {
    unsigned char left [BLOCKSIZE/2];
    unsigned char right [BLOCKSIZE/2];
}block;

void sp_network(unsigned char * data, unsigned char * key); 
void s_box(unsigned char * byte);
void p_box(unsigned char * data);
void feistel_block(unsigned char * left, unsigned char * right, unsigned char round_keys[NROUND][KEYSIZE]);
void schedule_key(unsigned char round_keys[NROUND][KEYSIZE], unsigned char * key);
unsigned char * feistel_encrypt(unsigned char * data, unsigned char * key, enum mode chosen);
unsigned char * feistel_decrypt(unsigned char * data, unsigned char * key, enum mode chosen);
unsigned char * operate_ecb_mode(block * b, int bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * operate_ctr_mode(block * b, int bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * encrypt_cbc_mode(block * b, int bnum, unsigned char round_keys[NROUND][KEYSIZE]);
unsigned char * decrypt_cbc_mode(block * b, int bnum, unsigned char round_keys[NROUND][KEYSIZE]);