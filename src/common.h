#define BUFSIZE 48000000
#define DEFAULT_MODE ctr
#define DEFAULT_OP enc
#define DEFAULT_OUT replace
#define BLOCKSIZE 16
#define KEYSIZE 8
#define NROUND 10

enum operation{enc, dec};
enum mode{cbc, ecb, ctr};
enum outmode{specified, replace};

//this structure represents the state of a block throught the rounds
typedef struct block {
    unsigned char left [BLOCKSIZE/2];
    unsigned char right [BLOCKSIZE/2];
}block;