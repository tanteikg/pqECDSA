 /*
 ============================================================================
 Name        : pqECDSA_shared.h
 Author      : Teik Guan Tan (modified from Sobuno)
 Version     : 0.1
 Description : common functions for zkboo layering into ECDSA 
 ============================================================================
 */

#ifndef SHARED_H_
#define SHARED_H_
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <gmp.h>
#include <openssl/rand.h>
#include "omp.h"

#define VERBOSE TRUE 
#define MSG_SIZE 32
#define BLOCK_SIZE 64  // 512 bits

// secp256r1 or prime256v1 parameters
#define CURVE_P "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
#define CURVE_N "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define CURVE_A "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
#define CURVE_B "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
#define CURVE_Gx "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
#define CURVE_Gy "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"


static const uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

//#define ySize 736
#define ySize 4864  // 728 + 8 + (256*8*2) + 32 
#define RANDSize 3044  // 2912 + 32*1  -- in blocks of 16

typedef struct {
	unsigned char x[64];
	uint32_t y[ySize];
} View;

typedef struct {
	uint32_t yp[3][32]; // 256 +256 bits Nx,Ny, 256 bits R, 256 bits s
	unsigned char h[3][32];
} a;

typedef struct {
	unsigned char ke[16];
	unsigned char ke1[16];
	View ve;
	View ve1;
	unsigned char re[4];
	unsigned char re1[4];
} z;

#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))
#define CH(e,f,g) ((e & f) ^ ((~e) & g))


void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

/* TTG
EVP_CIPHER_CTX setupAES(unsigned char key[16]) {
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);


	// A 128 bit IV 
	unsigned char *iv = (unsigned char *)"01234567890123456";

	if(1 != EVP_EncryptInit_ex(&ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();

	return ctx;


}
*/

int hexToBin32(char * hex, unsigned char * bin)
{
	char * tempc;
	int i;

        memset(bin,0,32);
	tempc = hex;
	for (i=0;i<32;i++)
        {
		if ((*tempc >= '0') && (*tempc <= '9'))
			bin[i] = *tempc - '0';
		else if ((*tempc >= 'a') && (*tempc <= 'f'))
			bin[i] = *tempc - 'a' + 10;
		else if ((*tempc >= 'A') && (*tempc <= 'F'))
			bin[i] = *tempc - 'A' + 10;
		else
			break;
		tempc++;
		bin[i] <<= 4;
		if ((*tempc >= '0') && (*tempc <= '9'))
			bin[i] += *tempc - '0';
		else if ((*tempc >= 'a') && (*tempc <= 'f'))
			bin[i] += *tempc - 'a' + 10;
		else if ((*tempc >= 'A') && (*tempc <= 'F'))
			bin[i] += *tempc - 'A' + 10;
		else
			break;
		tempc++;
	}
}

int ecInvMod(MP_INT * inv, MP_INT * k, MP_INT * p)
{
	MP_INT bigt1,bigt2,bigs1,bigs2,bigr1,bigr2;
	MP_INT bigq,bigtemp1,bigtemp2;
	mpz_init(&bigt1);
	mpz_init(&bigt2);
	mpz_init(&bigs1);
	mpz_init(&bigs2);
	mpz_init(&bigr1);
	mpz_init(&bigr2);
	mpz_init(&bigq);
	mpz_init(&bigtemp1);
	mpz_init(&bigtemp2);

	if (mpz_cmp_ui(k,0)<0)
	{
		mpz_neg(&bigt2,k);
		ecInvMod(&bigt1,&bigt2,p);
		mpz_sub(inv,p,&bigt1);
	}
	else
	{
		mpz_set_ui(&bigs1,0);
		mpz_set_ui(&bigs2,1);
		mpz_set_ui(&bigt1,1);
		mpz_set_ui(&bigt2,0);
		mpz_set(&bigr1,p);
		mpz_set(&bigr2,k);

		while (mpz_cmp_ui(&bigr1,0))
		{
			mpz_div(&bigq,&bigr2,&bigr1);
			
			mpz_mul(&bigtemp1,&bigq,&bigr1);
			mpz_sub(&bigtemp2,&bigr2,&bigtemp1);
			mpz_set(&bigr2,&bigr1);
			mpz_mod(&bigr1,&bigtemp2,p);
			
			mpz_mul(&bigtemp1,&bigq,&bigs1);
			mpz_sub(&bigtemp2,&bigs2,&bigtemp1);
			mpz_set(&bigs2,&bigs1);
			mpz_mod(&bigs1,&bigtemp2,p);

			mpz_mul(&bigtemp1,&bigq,&bigt1);
			mpz_sub(&bigtemp2,&bigt2,&bigtemp1);
			mpz_set(&bigt2,&bigt1);
			mpz_mod(&bigt1,&bigtemp2,p);

		}

		mpz_mod(inv,&bigs2,p);

	}

	mpz_clear(&bigt1);
	mpz_clear(&bigt2);
	mpz_clear(&bigs1);
	mpz_clear(&bigs2);
	mpz_clear(&bigr1);
	mpz_clear(&bigr2);
	mpz_clear(&bigq);
	mpz_clear(&bigtemp1);
	mpz_clear(&bigtemp2);
	return 0;

}

int ecAddPoint(MP_INT * x1, MP_INT * y1, MP_INT * x2, MP_INT * y2)
{
	MP_INT biga,bigb,bigl;
	MP_INT bigt1,bigt2;
	MP_INT bigx3,bigy3;
	MP_INT bigp;

	mpz_init(&bigl);
	mpz_init(&bigt1);
	mpz_init(&bigt2);
	mpz_init(&bigx3);
	mpz_init(&bigy3);
	mpz_init_set_str(&biga,CURVE_A,16);
	mpz_init_set_str(&bigb,CURVE_B,16);
	mpz_init_set_str(&bigp,CURVE_P,16);

	if (!mpz_cmp_ui(x1,0) && (!mpz_cmp_ui(y1,0)))
	{
		mpz_set(x1,x2);
		mpz_set(y1,y2);
	}
	else if (mpz_cmp_ui(x2,0) || (mpz_cmp_ui(y2,0)))
	{
		if (mpz_cmp(x1,x2))    // not equal
		{
			mpz_sub(&bigt2,x1,x2);
			mpz_mod(&bigt1,&bigt2,&bigp);
			ecInvMod(&bigl,&bigt1,&bigp);

			mpz_sub(&bigt2,y1,y2);
			mpz_mod(&bigt1,&bigt2,&bigp);
			mpz_mul(&bigt2,&bigl,&bigt1);
			mpz_mod(&bigl,&bigt2,&bigp);

		}
		else
		{
			mpz_mul_ui(&bigt2,y1,2);
			mpz_mod(&bigt1,&bigt2,&bigp);
			ecInvMod(&bigl,&bigt1,&bigp);

			mpz_mul(&bigt1,x1,x1);
			mpz_mod(&bigt2,&bigt1,&bigp);
			mpz_mul_ui(&bigt1,&bigt2,3);
			mpz_add(&bigt2,&bigt1,&biga);
		
			mpz_mul(&bigt1,&bigl,&bigt2);
			mpz_mod(&bigl,&bigt1,&bigp);

		}	

		mpz_mul(&bigt1,&bigl,&bigl);
		mpz_mod(&bigt2,&bigt1,&bigp);
		mpz_sub(&bigt1,&bigt2,x2);
		mpz_sub(&bigt2,&bigt1,x1);
		mpz_mod(&bigx3,&bigt2,&bigp);

		mpz_sub(&bigt2,x2,&bigx3);
		mpz_mod(&bigt1,&bigt2,&bigp);
		mpz_mul(&bigt2,&bigl,&bigt1);
		mpz_mod(&bigt1,&bigt2,&bigp);
		mpz_sub(&bigt2,&bigt1,y2);
		mpz_mod(&bigy3,&bigt2,&bigp);
	
		mpz_set(x1,&bigx3);
		mpz_set(y1,&bigy3);
	}

	mpz_clear(&bigl);
	mpz_clear(&biga);
	mpz_clear(&bigb);
	mpz_clear(&bigp);
	mpz_clear(&bigt1);
	mpz_clear(&bigt2);
	mpz_clear(&bigx3);
	mpz_clear(&bigy3);
	
	return 0;
}

int ecMul(MP_INT * x, MP_INT * y, MP_INT * m)
{
	MP_INT bigx,bigy;
	unsigned long long i;
	int loop;
	MP_INT bigx1,bigy1;

	MP_INT multiple;

	mpz_init_set(&multiple,m);
	mpz_init_set(&bigx,x);
	mpz_init_set(&bigy,y);
	mpz_init_set_ui(&bigx1,0);
	mpz_init_set_ui(&bigy1,0);

	while (mpz_cmp_ui(&multiple,0))
	{
		i = mpz_get_ui(&multiple);
		mpz_div_2exp(&multiple,&multiple,64);
		for (loop = 0;loop < 64; loop++)
		{
			if (i & 0x01)
			{
				ecAddPoint(&bigx1,&bigy1,&bigx,&bigy);
			}
			ecAddPoint(&bigx,&bigy,&bigx,&bigy);
			i>>=1;
		}
	}
	mpz_set(x,&bigx1);
	mpz_set(y,&bigy1);

	mpz_clear(&bigx);
	mpz_clear(&bigx1);
	mpz_clear(&bigy);
	mpz_clear(&bigy1);
	mpz_clear(&multiple);
	return 0;

}

void getAllRandomness(unsigned char key[16], unsigned char randomness[2912]) {
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	unsigned char *iv = (unsigned char *)"01234567890123456";
	EVP_CIPHER_CTX_init(ctx);
	//ctx = setupAES(key);
	unsigned char *plaintext =
			(unsigned char *)"0000000000000000";
	int len;
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();
	for(int j=0;j<(RANDSize/16);j++) {
		if(1 != EVP_EncryptUpdate(ctx, &randomness[j*16], &len, plaintext, strlen ((char *)plaintext)))
			handleErrors();

	}
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
}

uint32_t getRandom32(unsigned char * randomness, int randCount) {
	uint32_t ret;
	memcpy(&ret, &randomness[randCount], 4);
	return ret;
}

int getRandom256(unsigned char * randomness, int randCount, unsigned char outbuf[32]) {
	
	if (outbuf)
	{
		memcpy(outbuf, &randomness[randCount], 32);
		return 0;
	}
	else
		return -1;
}


void init_EVP() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	//OPENSSL_config(NULL);
}

void cleanup_EVP() {
	EVP_cleanup();
	ERR_free_strings();
}

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, k, 16);
	SHA256_Update(&ctx, &v, sizeof(v));
	SHA256_Update(&ctx, r, 4);
	SHA256_Final(hash, &ctx);
}


void H3(uint32_t y[32], a* as, int s, int* es) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, y, 128);
	SHA256_Update(&ctx, as, sizeof(a)*s);
	SHA256_Final(hash, &ctx);

	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < s) {
		if(bitTracker >= SHA256_DIGEST_LENGTH*8) { //Generate new hash as we have run out of bits in the previous hash
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, sizeof(hash));
			SHA256_Final(hash, &ctx);
			bitTracker = 0;
		}

		int b1 = GETBIT(hash[bitTracker/8], bitTracker % 8);
		int b2 = GETBIT(hash[(bitTracker+1)/8], (bitTracker+1) % 8);
		if(b1 == 0) {
			if(b2 == 0) {
				es[i] = 0;
				bitTracker += 2;
				i++;
			} else {
				es[i] = 1;
				bitTracker += 2;
				i++;
			}
		} else {
			if(b2 == 0) {
				es[i] = 2;
				bitTracker += 2;
				i++;
			} else {
				bitTracker += 2;
			}
		}
	}

}

void output(View v, uint32_t* result) {
	memcpy(result, &v.y[ySize - 32], 128);
}

void ecReconstruct(uint32_t* x0, uint32_t* x1, uint32_t* x2, uint32_t* y0, uint32_t* y1, uint32_t* y2, unsigned char * resultx, unsigned char * resulty) {
	MP_INT bigtx[3];
	MP_INT bigty[3];
	size_t i;

	mpz_init(&bigtx[0]);
	mpz_init(&bigtx[1]);
	mpz_init(&bigtx[2]);
	mpz_init(&bigty[0]);
	mpz_init(&bigty[1]);
	mpz_init(&bigty[2]);

	mpz_import(&bigtx[0],8,1,4,0,0,x0);
	mpz_import(&bigtx[1],8,1,4,0,0,x1);
	mpz_import(&bigtx[2],8,1,4,0,0,x2);
	mpz_import(&bigty[0],8,1,4,0,0,y0);
	mpz_import(&bigty[1],8,1,4,0,0,y1);
	mpz_import(&bigty[2],8,1,4,0,0,y2);

	ecAddPoint(&bigtx[0],&bigty[0],&bigtx[1],&bigty[1]);
	ecAddPoint(&bigtx[0],&bigty[0],&bigtx[2],&bigty[2]);

	memset(resultx,0,32);
	memset(resulty,0,32);
	i = 32;
	mpz_export(resultx,&i,1,1,0,0,&bigtx[0]);
	i = 32;
	mpz_export(resulty,&i,1,1,0,0,&bigty[0]);

	mpz_clear(&bigtx[0]);
	mpz_clear(&bigtx[1]);
	mpz_clear(&bigtx[2]);
	mpz_clear(&bigty[0]);
	mpz_clear(&bigty[1]);
	mpz_clear(&bigty[2]);

}

void reconstruct(uint32_t* y0, uint32_t* y1, uint32_t* y2, unsigned char * result) {
	MP_INT bigt[3];
	MP_INT bigS;
	MP_INT mod;
	size_t i;

	mpz_init(&bigt[0]);
	mpz_init(&bigt[1]);
	mpz_init(&bigt[2]);
	mpz_init(&bigS);
	mpz_init_set_str(&mod,CURVE_N,16);

	mpz_import(&bigt[0],8,1,4,0,0,y0);
	mpz_import(&bigt[1],8,1,4,0,0,y1);
	mpz_import(&bigt[2],8,1,4,0,0,y2);

	mpz_add(&bigt[0],&bigt[0],&bigt[1]);
	mpz_add(&bigt[0],&bigt[0],&bigt[2]);
	mpz_mod(&bigS,&bigt[0],&mod);

	memset(result,0,32);
	i = 32;
	mpz_export(result,&i,1,1,0,0,&bigS);

	mpz_clear(&bigt[0]);
	mpz_clear(&bigt[1]);
	mpz_clear(&bigt[2]);
	mpz_clear(&bigS);
	mpz_clear(&mod);

}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
}

omp_lock_t *locks;

void openmp_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
  {
    omp_set_lock(&locks[type]);
  }
  else
  {
    omp_unset_lock(&locks[type]);
  }
}


unsigned long openmp_thread_id(void)
{
  return (unsigned long)omp_get_thread_num();
}

void openmp_thread_setup(void)
{
  int i;

  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (i=0; i<CRYPTO_num_locks(); i++)
  {
    omp_init_lock(&locks[i]);
  }

  CRYPTO_set_id_callback((unsigned long (*)())openmp_thread_id);
  CRYPTO_set_locking_callback((void (*)())openmp_locking_callback);
}

void openmp_thread_cleanup(void)
{
  int i;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    omp_destroy_lock(&locks[i]);
  OPENSSL_free(locks);
}


int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][RANDSize], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint32_t t = 0;

	t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	if(ve.y[*countY] != t) {
		return 1;
	}
	z[0] = t;
	z[1] = ve1.y[*countY];

	(*countY)++;
	return 0;
}


int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][RANDSize], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint8_t a[2], b[2];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^ve.y[*countY],i);
		a[1]=GETBIT(x[1]^ve1.y[*countY],i);

		b[0]=GETBIT(y[0]^ve.y[*countY],i);
		b[1]=GETBIT(y[1]^ve1.y[*countY],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		if(GETBIT(ve.y[*countY],i+1) != (t ^ (a[0]&b[0]) ^ GETBIT(ve.y[*countY],i) ^ GETBIT(r[0],i))) {
			return 1;
		}
	}

	z[0]=x[0]^y[0]^ve.y[*countY];
	z[1]=x[1]^y[1]^ve1.y[*countY];
	(*countY)++;
	return 0;
}

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
}


int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1, unsigned char randomness[2][RANDSize], int* randCount, int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR2(a, b, t0);
	mpc_XOR2(a, c, t1);
	if(mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(z, a, z);
	return 0;
}

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][RANDSize], int* randCount, int* countY) {

	uint32_t t0[3];
	mpc_XOR2(f,g,t0);
	if(mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(t0,g,z);


	return 0;
}

static int mpc_readBig(MP_INT *bigval, View view, int * countY)
{
//printf("view 0 [%u][%u][%u][%u][%u][%u][%u][%u]\n",view.y[*countY],view.y[*countY+1],view.y[*countY+2],view.y[*countY+3],view.y[*countY+4],view.y[*countY+5],view.y[*countY+6],view.y[*countY+7]);
	mpz_import(bigval,8,1,4,0,0,&(view.y[*countY]));
//printf("--Count is %d\n",(*countY));
        return 0;
}


int mpc_ecAddPoint_verify(MP_INT bigx1[2], MP_INT bigy1[2], MP_INT bigx[2], MP_INT bigy[2], View ve, View ve1, unsigned char randomness[2][RANDSize], int* randCount, int* countY) {

	MP_INT bigtx,bigty;
	int ret;

	mpz_init(&bigtx);
	mpz_init(&bigty);

/*
printf("Addpoint verify x1 ");
mpz_out_str(stdout,16,&bigx1[0]);
printf("\nx : ");
mpz_out_str(stdout,16,&bigx[0]);
printf("\n");
*/

	ecAddPoint(&bigx1[0],&bigy1[0],&bigx[1],&bigy[1]);
	mpc_readBig(&bigtx,ve,countY);

	ret = 0;
	if (mpz_cmp(&bigtx,&bigx1[0]))
		ret = 1;
	else 
		mpc_readBig(&bigx1[1],ve1,countY);

	(*countY) += 8;
	mpc_readBig(&bigty,ve,countY);

	if (mpz_cmp(&bigty,&bigy1[0]))
		ret = 1;
	else
		mpc_readBig(&bigy1[1],ve1,countY);

	(*countY) += 8;

	return ret;
}

int verify(a a, int e, z z) {
	unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
	H(z.ke, z.ve, z.re, hash);

	if (memcmp(a.h[e], hash, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	H(z.ke1, z.ve1, z.re1, hash);
	if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	free(hash);

	uint32_t* result = malloc(128);
	output(z.ve, result);
	if (memcmp(a.yp[e], result, 128) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	output(z.ve1, result);
	if (memcmp(a.yp[(e + 1) % 3], result, 128) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	free(result);

	unsigned char randomness[2][RANDSize];
	getAllRandomness(z.ke, randomness[0]);
	getAllRandomness(z.ke1, randomness[1]);

	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));
	*countY = 0;

	uint32_t w[64][2];

	for (int k = 0; k < 64;k++)
	{
		w[k][0] = w[k][1] = 0;
	}

	for (int j = 0; j < 16; j++) {
		w[j][0] = (z.ve.x[j * 4] << 24) | (z.ve.x[j * 4 + 1] << 16)
								| (z.ve.x[j * 4 + 2] << 8) | z.ve.x[j * 4 + 3];
		w[j][1] = (z.ve1.x[j * 4] << 24) | (z.ve1.x[j * 4 + 1] << 16)
								| (z.ve1.x[j * 4 + 2] << 8) | z.ve1.x[j * 4 + 3];
	}

	uint32_t s0[2], s1[2];
	uint32_t t0[2], t1[2];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE2(w[j-15], 7, t0);
		mpc_RIGHTROTATE2(w[j-15], 18, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTSHIFT2(w[j-15], 3, t1);
		mpc_XOR2(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE2(w[j-2], 17, t0);
		mpc_RIGHTROTATE2(w[j-2], 19, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTSHIFT2(w[j-2],10,t1);
		mpc_XOR2(t0, t1, s1);

		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

		if(mpc_ADD_verify(w[j-16], s0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}


		if(mpc_ADD_verify(w[j-7], t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}
		if(mpc_ADD_verify(t1, s1, w[j], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}

	}


	uint32_t va[2] = { hA[0],hA[0] };
	uint32_t vb[2] = { hA[1],hA[1] };
	uint32_t vc[2] = { hA[2],hA[2] };
	uint32_t vd[2] = { hA[3],hA[3] };
	uint32_t ve[2] = { hA[4],hA[4] };
	uint32_t vf[2] = { hA[5],hA[5] };
	uint32_t vg[2] = { hA[6],hA[6] };
	uint32_t vh[2] = { hA[7],hA[7] };
	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE2(ve, 6, t0);
		mpc_RIGHTROTATE2(ve, 11, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(ve, 25, t1);
		mpc_XOR2(t0, t1, s1);




		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		if(mpc_ADD_verify(vh, s1, t0, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		if(mpc_CH_verify(ve, vf, vg, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//t1 = t0 + t1 (h+s1+ch)
		if(mpc_ADD_verify(t0, t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		t0[0] = k[i];
		t0[1] = k[i];
		if(mpc_ADD_verify(t1, t0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		if(mpc_ADD_verify(t1, w[i], temp1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE2(va, 2, t0);
		mpc_RIGHTROTATE2(va, 13, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(va, 22, t1);
		mpc_XOR2(t0, t1, s0);

		//maj = (a & (b ^ c)) ^ (b & c);
		//(a & b) ^ (a & c) ^ (b & c)

		if(mpc_MAJ_verify(va, vb, vc, maj, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//temp2 = s0+maj;
		if(mpc_ADD_verify(s0, maj, temp2, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		memcpy(vh, vg, sizeof(uint32_t) * 2);
		memcpy(vg, vf, sizeof(uint32_t) * 2);
		memcpy(vf, ve, sizeof(uint32_t) * 2);
		//e = d+temp1;
		if(mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		memcpy(vd, vc, sizeof(uint32_t) * 2);
		memcpy(vc, vb, sizeof(uint32_t) * 2);
		memcpy(vb, va, sizeof(uint32_t) * 2);
		//a = temp1+temp2;

		if(mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}
	}

	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
	if(mpc_ADD_verify(hHa[0], va, hHa[0], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[1], vb, hHa[1], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[2], vc, hHa[2], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[3], vd, hHa[3], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[4], ve, hHa[4], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[5], vf, hHa[5], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[6], vg, hHa[6], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[7], vh, hHa[7], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	// ecc verification
	{
		unsigned char results[2][32];
		unsigned long long i[2];
		MP_INT multiple[2],bigi[2];
		MP_INT bigx[2],bigy[2];
		MP_INT bigtx[2],bigty[2];
		MP_INT bigx1[2],bigy1[2];
		int j,k, loop;
		int ret = 0;


		for (j = 0; j < 8; j++) {
			mpc_RIGHTSHIFT2(hHa[j], 24, t0);
				results[0][j * 4] = t0[0];
				results[1][j * 4] = t0[1];
			mpc_RIGHTSHIFT2(hHa[j], 16, t0);
				results[0][j * 4 + 1] = t0[0];
				results[1][j * 4 + 1] = t0[1];
			mpc_RIGHTSHIFT2(hHa[j], 8, t0);
				results[0][j * 4 + 2] = t0[0];
				results[1][j * 4 + 2] = t0[1];

			results[0][j * 4 + 3] = hHa[j][0];
			results[1][j * 4 + 3] = hHa[j][1];
		}

		for (j=0;j<2;j++)
		{
			mpz_init(&multiple[j]);
			mpz_init(&bigi[j]);
			mpz_init(&bigtx[j]);
			mpz_init(&bigty[j]);
			mpz_init_set_str(&bigx[j],CURVE_Gx,16);
			mpz_init_set_str(&bigy[j],CURVE_Gy,16);
			mpz_init_set_ui(&bigx1[j],0);
			mpz_init_set_ui(&bigy1[j],0);
		}

		// check that at least 1 of the hashes match private key
 
		mpz_import(&multiple[0],32,1,1,0,0,results[0]);
		mpz_import(&multiple[1],32,1,1,0,0,results[1]);
		mpc_readBig(&bigi[0],z.ve,countY);
		mpc_readBig(&bigi[1],z.ve1,countY);
		(*countY)+=8;
		if (mpz_cmp(&multiple[0],&bigi[0]) && mpz_cmp(&multiple[1],&bigi[0]) && mpz_cmp(&multiple[0],&bigi[1]) && mpz_cmp(&multiple[1],&bigi[1]))
		{
			ret = -1;
		}	

		// verify ecc public key here
		for (k = 0; (k < 4)&& (ret ==0); k++)
		{
			i[0] = mpz_get_ui(&bigi[0]);
			i[1] = mpz_get_ui(&bigi[1]);

			mpz_div_2exp(&bigi[0],&bigi[0],64);
			mpz_div_2exp(&bigi[1],&bigi[1],64);

			for (loop = 0;(loop < 64) && (ret == 0); loop++)
			{
				for (j=0;j<2;j++)
				{
					if (i[j] & 0x01)
					{
						mpz_set(&bigtx[j],&bigx[j]);
						mpz_set(&bigty[j],&bigy[j]);
					}
					else
					{
						mpz_set_ui(&bigtx[j],0);
						mpz_set_ui(&bigty[j],0);
					}
					i[j]>>=1;
				}
/*

{
int tt;
printf("loop %d:\n",k*64+loop);
for (tt = 0; tt< 2;tt++)
{
printf("x %d:",tt);
mpz_out_str(stdout,16,&bigx1[tt]);
printf("\n");
printf("y %d:",tt);
mpz_out_str(stdout,16,&bigy1[tt]);
printf("\n");
}
for (tt = 0; tt< 2;tt++)
{
printf("tempx %d:",tt);
mpz_out_str(stdout,16,&bigtx[tt]);
printf("\n");
printf("tempy %d:",tt);
mpz_out_str(stdout,16,&bigty[tt]);
printf("\n");
}
}
*/


				ret = mpc_ecAddPoint_verify(bigx1,bigy1,bigtx,bigty,z.ve,z.ve1,randomness,randCount,countY);
				ecAddPoint(&bigx[0],&bigy[0],&bigx[0],&bigy[0]);
				ecAddPoint(&bigx[1],&bigy[1],&bigx[1],&bigy[1]);

			}
		}

		// now to check that the final value must belong to the pub key parts
		{
			size_t k;

			mpz_import(&bigx[0],8,1,4,0,0,a.yp[e]);
			
			ret = mpz_cmp(&bigx1[0],&bigx[0]);
		}

		for (j=0;j<2;j++)
		{
			mpz_clear(&bigi[j]);
			mpz_clear(&bigx[j]);
			mpz_clear(&bigx1[j]);
			mpz_clear(&bigy[j]);
			mpz_clear(&bigy1[j]);
			mpz_clear(&bigtx[j]);
			mpz_clear(&bigty[j]);
			mpz_clear(&multiple[j]);
		}

		if (ret)
		{
			return ret;
		}

	}

	free(randCount);
	free(countY);

	return 0;
}


#endif /* SHARED_H_ */
