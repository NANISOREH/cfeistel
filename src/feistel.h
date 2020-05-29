#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 10
#define DEFAULT_MODE ecb
#define DEFAULT_OP enc

enum operation{enc, dec};
enum mode{cbc, ecb}; 

//this structure represents the state of a block throught the rounds
typedef struct block {
    unsigned char left [BLOCKSIZE/2];
    unsigned char right [BLOCKSIZE/2];
    unsigned char round_keys [NROUND][KEYSIZE];
}block;

void sp_network(unsigned char * data, unsigned char * key); 
void s_box(unsigned char * byte);
void feistel_block(unsigned char * left, unsigned char * right, unsigned char round_keys[NROUND][KEYSIZE]);
void schedule_key(unsigned char round_keys[NROUND][KEYSIZE], unsigned char * key);
unsigned char * feistel(unsigned char * data, unsigned char * key, enum mode chosen, enum operation to_do);
unsigned char * operate_ecb_mode(block * b, int bnum);
unsigned char * encrypt_cbc_mode(block * b, int bnum);
unsigned char * decrypt_cbc_mode(block * b, int bnum);