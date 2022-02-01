/*

        Name: pqECDSA_prove.c
        Author: Tan Teik Guan
        Description: prove function for pq resistance for ECDSA using ZKBoo. Modified from MPC_SHA256.c
*/
	
/*
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
  
 */


#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "pqECDSA_shared.h"
#include "omp.h"



int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;
int NUM_ROUNDS = 100; 
int numLoops = 1;


uint32_t rand32() {
	uint32_t x;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;

	return x;
}

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
	z[2] = x[2] ^ y[2];
}



void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;
	uint32_t t[3] = { 0 };

	t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
	t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
	z[0] = t[0];
	z[1] = t[1];
	z[2] = t[2];
	views[0].y[*countY] = z[0];
	views[1].y[*countY] = z[1];
	views[2].y[*countY] = z[2];
	(*countY)++;
}



void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
	z[2] = ~x[2];
}



void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y[0]^c[0],i);
		b[1]=GETBIT(y[1]^c[1],i);
		b[2]=GETBIT(y[2]^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y[0]^c[0];
	z[1]=x[1]^y[1]^c[1];
	z[2]=x[2]^y[2]^c[2];


	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;


}


void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y^c[0],i);
		b[1]=GETBIT(y^c[1],i);
		b[2]=GETBIT(y^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y^c[0];
	z[1]=x[1]^y^c[1];
	z[2]=x[2]^y^c[2];


	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;

}


int sha256(unsigned char* result, unsigned char* input, int numBits) {
	uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };


	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}
	int chars = numBits >> 3;
	unsigned char* chunk = calloc(64, 1); //512 bits
	memcpy(chunk, input, chars);
	chunk[chars] = 0x80;
	//Last 8 chars used for storing length of input without padding, in big-endian.
	//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

	//chunk[60] = numBits >> 24;
	//chunk[61] = numBits >> 16;
	chunk[62] = numBits >> 8;
	chunk[63] = numBits;

	uint32_t w[64];
	int i;
	for (i = 0; i < 16; i++) {
		w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16)
						| (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
	}

	uint32_t s0, s1;
	for (i = 16; i < 64; i++) {
		s0 = RIGHTROTATE(w[i - 15], 7) ^ RIGHTROTATE(w[i - 15], 18)
						^ (w[i - 15] >> 3);
		s1 = RIGHTROTATE(w[i - 2], 17) ^ RIGHTROTATE(w[i - 2], 19)
						^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a, b, c, d, e, f, g, h, temp1, temp2, maj;
	a = hA[0];
	b = hA[1];
	c = hA[2];
	d = hA[3];
	e = hA[4];
	f = hA[5];
	g = hA[6];
	h = hA[7];

	for (i = 0; i < 64; i++) {
		s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);

		temp1 = h + s1 + CH(e, f, g) + k[i] + w[i];
		s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);


		maj = (a & (b ^ c)) ^ (b & c);
		temp2 = s0 + maj;


		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

	}

	hA[0] += a;
	hA[1] += b;
	hA[2] += c;
	hA[3] += d;
	hA[4] += e;
	hA[5] += f;
	hA[6] += g;
	hA[7] += h;

	for (i = 0; i < 8; i++) {
		result[i * 4] = (hA[i] >> 24);
		result[i * 4 + 1] = (hA[i] >> 16);
		result[i * 4 + 2] = (hA[i] >> 8);
		result[i * 4 + 3] = hA[i];
	}
	return 0;
}

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
	z[2] = RIGHTROTATE(x[2], i);
}




void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
	z[2] = x[2] >> i;
}





void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	mpc_AND(t0, t1, z, randomness, randCount, views, countY);
	mpc_XOR(z, a, z);
}


void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	mpc_AND(e,t0,t0, randomness, randCount, views, countY);
	mpc_XOR(t0,g,z);

}



int mpc_sha256(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3], int* randCount, View views[3], int* countY) {



	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}


	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint32_t w[64][3];
	uint32_t msg[MSG_SIZE/4];

	for (int i =0; i<64;i++)
	{
		w[i][0]=w[i][1]=w[i][2] = 0;
	}			

	for (int i = 0; i < 3; i++) {
		chunks[i] = calloc(64, 1); //512 bits
		memcpy(chunks[i], inputs[i], chars);
		chunks[i][chars] = 0x80;
		//Last 8 chars used for storing length of input without padding, in big-endian.
		//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

		//chunk[60] = numBits >> 24;
		//chunk[61] = numBits >> 16;
		chunks[i][62] = numBits >> 8;
		chunks[i][63] = numBits;
		memcpy(views[i].x, chunks[i], 64);

		for (int j = 0; j < 16; j++) {
			w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16)
							| (chunks[i][j * 4 + 2] << 8) | chunks[i][j * 4 + 3];
		}
		free(chunks[i]);
	}

	uint32_t s0[3], s1[3];
	uint32_t t0[3], t1[3];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE(w[j-15], 7, t0);

		mpc_RIGHTROTATE(w[j-15], 18, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-15], 3, t1);
		mpc_XOR(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE(w[j-2], 17, t0);
		mpc_RIGHTROTATE(w[j-2], 19, t1);

		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-2], 10, t1);
		mpc_XOR(t0, t1, s1);

		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

		mpc_ADD(w[j-16], s0, t1, randomness, randCount, views, countY);
		mpc_ADD(w[j-7], t1, t1, randomness, randCount, views, countY);
		mpc_ADD(t1, s1, w[j], randomness, randCount, views, countY);

	}

	uint32_t a[3] = { hA[0],hA[0],hA[0] };
	uint32_t b[3] = { hA[1],hA[1],hA[1] };
	uint32_t c[3] = { hA[2],hA[2],hA[2] };
	uint32_t d[3] = { hA[3],hA[3],hA[3] };
	uint32_t e[3] = { hA[4],hA[4],hA[4] };
	uint32_t f[3] = { hA[5],hA[5],hA[5] };
	uint32_t g[3] = { hA[6],hA[6],hA[6] };
	uint32_t h[3] = { hA[7],hA[7],hA[7] };
	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 6, t0);
		mpc_RIGHTROTATE(e, 11, t1);
		mpc_XOR(t0, t1, t0);

		mpc_RIGHTROTATE(e, 25, t1);
		mpc_XOR(t0, t1, s1);


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		mpc_ADD(h, s1, t0, randomness, randCount, views, countY);


		mpc_CH(e, f, g, t1, randomness, randCount, views, countY);

		//t1 = t0 + t1 (h+s1+ch)
		mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);

		mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);

		mpc_ADD(t1, w[i], temp1, randomness, randCount, views, countY);

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 2, t0);
		mpc_RIGHTROTATE(a, 13, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTROTATE(a, 22, t1);
		mpc_XOR(t0, t1, s0);


		mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);

		//temp2 = s0+maj;
		mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);

		memcpy(h, g, sizeof(uint32_t) * 3);
		memcpy(g, f, sizeof(uint32_t) * 3);
		memcpy(f, e, sizeof(uint32_t) * 3);
		//e = d+temp1;
		mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
		memcpy(d, c, sizeof(uint32_t) * 3);
		memcpy(c, b, sizeof(uint32_t) * 3);
		memcpy(b, a, sizeof(uint32_t) * 3);
		//a = temp1+temp2;

		mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
	}

	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
	mpc_ADD(hHa[0], a, hHa[0], randomness, randCount, views, countY);
	mpc_ADD(hHa[1], b, hHa[1], randomness, randCount, views, countY);
	mpc_ADD(hHa[2], c, hHa[2], randomness, randCount, views, countY);
	mpc_ADD(hHa[3], d, hHa[3], randomness, randCount, views, countY);
	mpc_ADD(hHa[4], e, hHa[4], randomness, randCount, views, countY);
	mpc_ADD(hHa[5], f, hHa[5], randomness, randCount, views, countY);
	mpc_ADD(hHa[6], g, hHa[6], randomness, randCount, views, countY);
	mpc_ADD(hHa[7], h, hHa[7], randomness, randCount, views, countY);

	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		results[0][i * 4] = t0[0];
		results[1][i * 4] = t0[1];
		results[2][i * 4] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		results[0][i * 4 + 1] = t0[0];
		results[1][i * 4 + 1] = t0[1];
		results[2][i * 4 + 1] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		results[0][i * 4 + 2] = t0[0];
		results[1][i * 4 + 2] = t0[1];
		results[2][i * 4 + 2] = t0[2];

		results[0][i * 4 + 3] = hHa[i][0];
		results[1][i * 4 + 3] = hHa[i][1];
		results[2][i * 4 + 3] = hHa[i][2];
	}

	return 0;
}


int writeToFile(char filename[], void* data, int size, int numItems) {
	FILE *file;

	file = fopen(filename, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(data, size, numItems, file);
	fclose(file);
	return 0;
}




int secretShare(unsigned char* input, int numBytes, unsigned char output[3][numBytes]) {
	if(RAND_bytes(output[0], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	if(RAND_bytes(output[1], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	for (int j = 0; j < numBytes; j++) {
		output[2][j] = input[j] ^ output[0][j] ^ output[1][j];
	}
	return 0;
}

static int mpc_writeBig(MP_INT bigval[3], View views[3], int * countY)
{
	size_t i;
	int j;
	uint32_t buf[3][8];

	for (j=0;j<3;j++)
	{
		memset(buf[j],0,32);
		i = 8;
		mpz_export(buf[j],(size_t *)&i,1,4,0,0,&bigval[j]);
		if (i < 8)
		{
			memset(buf[j],0,32);
			
			mpz_export(&(buf[j][8-i]),(size_t *)&i,1,4,0,0,&bigval[j]);
		}

	}
	for (j=0;j<8;j++)
	{
		views[0].y[*countY] = buf[0][j];
		views[1].y[*countY] = buf[1][j];
		views[2].y[*countY] = buf[2][j];
		(*countY)++;
	}
	return 0;
}


	

int mpc_ecAddPoint(MP_INT bigx1[3],MP_INT bigy1[3], MP_INT bigx[3], MP_INT bigy[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY)
{
	// do we need to add random ? I think not...

	ecAddPoint(&bigx1[0],&bigy1[0],&bigx[1],&bigy[1]);
	ecAddPoint(&bigx1[1],&bigy1[1],&bigx[2],&bigy[2]);
	ecAddPoint(&bigx1[2],&bigy1[2],&bigx[0],&bigy[0]);

	// write some stuff
	mpc_writeBig(bigx1,views,countY);
	mpc_writeBig(bigy1,views,countY);

	return 0;

}

int mpc_ecMultiply(unsigned char * Prodx[3], unsigned char * Prody[3], unsigned char * hashes[3],unsigned char *randomness[3], int* randCount, View views[3], int* countY)
{
	MP_INT bigx[3],bigy[3];
	MP_INT bigtx[3],bigty[3];
	unsigned long long i[3];  // 64 bit
	int j,loop;
	size_t k;
	MP_INT bigx1[3],bigy1[3];
	MP_INT multiple[3];
	MP_INT priv;
	MP_INT mod;
	unsigned char privkey[32];

	for (j=0;j<32;j++)
		privkey[j] = hashes[0][j]^hashes[1][j]^hashes[2][j]; 
	mpz_init(&priv);
	mpz_import(&priv,32,1,1,0,0,privkey);
	mpz_init_set_str(&mod,CURVE_N,16);
	for (j=0;j<3;j++)
	{
		mpz_init(&multiple[j]);
		mpz_init(&bigtx[j]);
		mpz_init(&bigty[j]);
		mpz_init_set_str(&bigx[j],CURVE_Gx,16);
		mpz_init_set_str(&bigy[j],CURVE_Gy,16);
		mpz_import(&multiple[j],32,1,1,0,0,hashes[j]);
		mpz_init_set_ui(&bigx1[j],0);
		mpz_init_set_ui(&bigy1[j],0);
	}

	// need to adjust multiple[2] to be mod N 
	mpz_mod(&multiple[0],&multiple[0],&mod);
	mpz_mod(&multiple[1],&multiple[1],&mod);
	mpz_add(&multiple[2],&multiple[0],&multiple[1]);
	mpz_sub(&multiple[2],&priv,&multiple[2]);
	mpz_mod(&multiple[2],&multiple[2],&mod);

	mpc_writeBig(multiple,views,countY);

	for (k = 0; k < 4; k++)
	{
		i[0] = mpz_get_ui(&multiple[0]);
		i[1] = mpz_get_ui(&multiple[1]);
		i[2] = mpz_get_ui(&multiple[2]);
		mpz_div_2exp(&multiple[0],&multiple[0],64);
		mpz_div_2exp(&multiple[1],&multiple[1],64);
		mpz_div_2exp(&multiple[2],&multiple[2],64);
		for (loop = 0;loop < 64; loop++)
		{
			for (j=0;j<3;j++)
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
printf("loop %d:\n",(k*64)+loop);
for (tt = 0; tt< 3;tt++)
{
printf("x %d:",tt);
mpz_out_str(stdout,16,&bigx1[tt]);
printf("\n");
printf("y %d:",tt);
mpz_out_str(stdout,16,&bigy1[tt]);
printf("\n");
}
for (tt = 0; tt< 3;tt++)
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

			mpc_ecAddPoint(bigx1,bigy1,bigtx,bigty,randomness,randCount,views,countY);
			ecAddPoint(&bigx[0],&bigy[0],&bigx[0],&bigy[0]);
			ecAddPoint(&bigx[1],&bigy[1],&bigx[1],&bigy[1]);
			ecAddPoint(&bigx[2],&bigy[2],&bigx[2],&bigy[2]);

		}
	}

	for (j=0;j<3;j++)
	{
		memset(Prodx[j],0,32);
		memset(Prody[j],0,32);
		k = 32; // just using as a temp variable
		mpz_export(Prodx[j],(size_t *)&k,1,1,0,0,&bigx1[j]);
		if (k < 32)
		{
			memset(Prodx[j],0,32);
			mpz_export(&(Prodx[j][32-k]),(size_t *)&k,1,1,0,0,&bigx1[j]);
		}
		k = 32; // just using as a temp variable
		mpz_export(Prody[j],(size_t *)&k,1,1,0,0,&bigy1[j]);
		if (k < 32)
		{
			memset(Prody[j],0,32);
			mpz_export(&(Prody[j][32-k]),(size_t *)&k,1,1,0,0,&bigy1[j]);
		}
	}

	for (j=0;j<3;j++)
	{
		mpz_clear(&bigx[j]);
		mpz_clear(&bigx1[j]);
		mpz_clear(&bigy[j]);
		mpz_clear(&bigy1[j]);
		mpz_clear(&bigtx[j]);
		mpz_clear(&bigty[j]);
		mpz_clear(&multiple[j]);
	}

	mpz_clear(&priv);
	mpz_clear(&mod);
	return 0;

}

static int mpc_mpz_mul(MP_INT result[3], MP_INT val[3], MP_INT * multiple,unsigned char *randomness[3], int* randCount,  View views[3], int* countY)
{
	int j;
	MP_INT mod;
	unsigned char buf[32];
	mpz_init_set_str(&mod,CURVE_N,16);


	for (j=0;j<3;j++)
	{
		mpz_mul(&result[j],&val[j],multiple);
		mpz_mod(&result[j],&result[j],&mod);
	}

//	mpc_writeBig(result,views,countY);

	mpz_clear(&mod);
	return 0;
}


int mpc_ecDSA(unsigned char * R[3], unsigned char * s[3], unsigned char * hashes[3],unsigned char tbs[32], unsigned char r[32], unsigned char *randomness[3], int* randCount, View views[3], int* countY)
{
	int j;
	size_t k;
	MP_INT bigi[3]; // 3-part private key
	MP_INT priv;
	MP_INT mod;
	unsigned char privkey[32];
	MP_INT bigk,biginvk;
	MP_INT bigRx,bigRy,bigH;
	MP_INT bigt1[3],bigt2[3];
	unsigned char buf[32];
	MP_INT bigh[3];

	mpz_init(&bigt1[0]);
	mpz_init(&bigt1[1]);
	mpz_init(&bigt1[2]);
	mpz_init(&bigt2[0]);
	mpz_init(&bigt2[1]);
	mpz_init(&bigt2[2]);
	mpz_init(&bigk);
	mpz_init(&bigH);
	mpz_init(&biginvk);

	for (j=0;j<32;j++)
		privkey[j] = hashes[0][j]^hashes[1][j]^hashes[2][j]; 
	mpz_init(&priv);
	mpz_import(&priv,32,1,1,0,0,privkey);
	mpz_init_set_str(&mod,CURVE_N,16);

	for (j=0;j<3;j++)
	{
		mpz_init(&bigh[j]);
		mpz_init(&bigi[j]);
		mpz_import(&bigi[j],32,1,1,0,0,hashes[j]);
	}

	// need to adjust bigi[2] to be mod N 
	mpz_mod(&bigi[0],&bigi[0],&mod);
	mpz_mod(&bigi[1],&bigi[1],&mod);
	mpz_add(&bigi[2],&bigi[0],&bigi[1]);
	mpz_sub(&bigi[2],&priv,&bigi[2]);
	mpz_mod(&bigi[2],&bigi[2],&mod);

	// get random into bigk
	mpz_import(&bigk,32,1,1,0,0,r);

	ecInvMod(&biginvk,&bigk,&mod);
	mpz_init_set_str(&bigRx,CURVE_Gx,16);
	mpz_init_set_str(&bigRy,CURVE_Gy,16);
	ecMul(&bigRx,&bigRy,&bigk);
	
	mpz_import(&bigH,32,1,1,0,0,tbs);

	getRandom256(randomness[0],*randCount,buf);
	mpz_import(&bigh[0],32,1,1,0,0,buf);	
	getRandom256(randomness[1],*randCount,buf);
	mpz_import(&bigh[1],32,1,1,0,0,buf);	
	*randCount+=32;
	mpz_sub(&bigh[2],&bigH,&bigh[0]);
	mpz_sub(&bigh[2],&bigh[2],&bigh[1]);
	mpz_mod(&bigh[2],&bigh[2],&mod);
		
	mpc_mpz_mul(bigt1,bigi,&bigRx,randomness, randCount, views, countY);
//	mpc_writeBig(bigt1,views,countY);

//	mpc_writeBig(bigh,views,countY);
	for (j=0;j<3;j++)
	{
		mpz_add(&bigt2[j],&bigh[j],&bigt1[j]);
		mpz_mod(&bigt1[j],&bigt2[j],&mod);
	}
//	mpc_writeBig(bigt2,views,countY);

	mpc_mpz_mul(bigt2,bigt1,&biginvk, randomness, randCount, views, countY);
//	mpc_writeBig(bigt2,views,countY);

	
	for (j=0;j<3;j++)
	{
		memset(s[j],0,32);
		memset(R[j],0,32);
		k = 32;
		mpz_export(s[j],(size_t *)&k,1,1,0,0,&bigt2[j]);
		k = 32;
		mpz_export(R[j],(size_t *)&k,1,1,0,0,&bigRx);
	}

	for (j=0;j<3;j++)
	{
		mpz_clear(&bigt1[j]);
		mpz_clear(&bigt2[j]);
		mpz_clear(&bigi[j]);
		mpz_clear(&bigh[j]);
	}
	mpz_clear(&bigk);
	mpz_clear(&mod);
	mpz_clear(&bigH);
	mpz_clear(&biginvk);
	mpz_clear(&priv);
	mpz_clear(&bigRx);
	mpz_clear(&bigRy);


	return 0;
}



int commit(int numBytes, unsigned char shares[3][numBytes], unsigned char tbs[32], unsigned char r[32], unsigned char *randomness[3], unsigned char rs[3][4], View views[3], a * as) {

	unsigned char* inputs[3];
	inputs[0] = shares[0];
	inputs[1] = shares[1];
	inputs[2] = shares[2];
	unsigned char* hashes[3];
	hashes[0] = malloc(32);
	hashes[1] = malloc(32);
	hashes[2] = malloc(32);
	unsigned char* Pubx[3];
	Pubx[0] = malloc(32);
	Pubx[1] = malloc(32);
	Pubx[2] = malloc(32);
	unsigned char* Puby[3];
	Puby[0] = malloc(32);
	Puby[1] = malloc(32);
	Puby[2] = malloc(32);
	unsigned char* R[3];
	R[0] = malloc(32);
	R[1] = malloc(32);
	R[2] = malloc(32);
	unsigned char* s[3];
	s[0] = malloc(32);
	s[1] = malloc(32);
	s[2] = malloc(32);

	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));
	*countY = 0;
	*randCount = 0;
	mpc_sha256(hashes, inputs, numBytes * 8, randomness, randCount, views, countY);
/*
printf("private key is: ");
for (int i = 0; i < 32; i++)
{
  printf("%02X",hashes[0][i]^hashes[1][i]^hashes[2][i]);
}
printf("\n");

*/

	// compute public key N
	mpc_ecMultiply(Pubx,Puby,hashes,randomness, randCount, views, countY);

	// sign to get R,s
	mpc_ecDSA(R,s,hashes,tbs,r,randomness,randCount,views,countY);

	//Explicitly add y to view
	free(randCount);
	for(int i = 0; i<8; i++) {
		views[0].y[*countY] = 		(Pubx[0][i * 4] << 24) | (Pubx[0][i * 4 + 1] << 16) | (Pubx[0][i * 4 + 2] << 8) | Pubx[0][i * 4 + 3];
		views[1].y[*countY] = 		(Pubx[1][i * 4] << 24) | (Pubx[1][i * 4 + 1] << 16) | (Pubx[1][i * 4 + 2] << 8) | Pubx[1][i * 4 + 3];
		views[2].y[*countY] = 		(Pubx[2][i * 4] << 24) | (Pubx[2][i * 4 + 1] << 16) | (Pubx[2][i * 4 + 2] << 8) | Pubx[2][i * 4 + 3];
		*countY += 1;
	}

	for(int i = 0; i<8; i++) {
		views[0].y[*countY] = 		(Puby[0][i * 4] << 24) | (Puby[0][i * 4 + 1] << 16) | (Puby[0][i * 4 + 2] << 8) | Puby[0][i * 4 + 3];
		views[1].y[*countY] = 		(Puby[1][i * 4] << 24) | (Puby[1][i * 4 + 1] << 16) | (Puby[1][i * 4 + 2] << 8) | Puby[1][i * 4 + 3];
		views[2].y[*countY] = 		(Puby[2][i * 4] << 24) | (Puby[2][i * 4 + 1] << 16) | (Puby[2][i * 4 + 2] << 8) | Puby[2][i * 4 + 3];
		*countY += 1;
	}

	for(int i = 0; i<8; i++) {
		views[0].y[*countY] = 		(R[0][i * 4] << 24) | (R[0][i * 4 + 1] << 16) | (R[0][i * 4 + 2] << 8) | R[0][i * 4 + 3];
		views[1].y[*countY] = 		(R[1][i * 4] << 24) | (R[1][i * 4 + 1] << 16) | (R[1][i * 4 + 2] << 8) | R[1][i * 4 + 3];
		views[2].y[*countY] = 		(R[2][i * 4] << 24) | (R[2][i * 4 + 1] << 16) | (R[2][i * 4 + 2] << 8) | R[2][i * 4 + 3];
		*countY += 1;
	}
	for(int i = 0; i<8; i++) {
		views[0].y[*countY] = 		(s[0][i * 4] << 24) | (s[0][i * 4 + 1] << 16) | (s[0][i * 4 + 2] << 8) | s[0][i * 4 + 3];
		views[1].y[*countY] = 		(s[1][i * 4] << 24) | (s[1][i * 4 + 1] << 16) | (s[1][i * 4 + 2] << 8) | s[1][i * 4 + 3];
		views[2].y[*countY] = 		(s[2][i * 4] << 24) | (s[2][i * 4 + 1] << 16) | (s[2][i * 4 + 2] << 8) | s[2][i * 4 + 3];
		*countY += 1;
	}


	uint32_t* result1 = malloc(128);
	output(views[0], result1);
	uint32_t* result2 = malloc(128);
	output(views[1], result2);
	uint32_t* result3 = malloc(128);
	output(views[2], result3);

//	a a;
	memcpy(as->yp[0], result1, 128);
	memcpy(as->yp[1], result2, 128);
	memcpy(as->yp[2], result3, 128);

	free(result1);
	free(result2);
	free(result3);

	free(countY);
	free(hashes[0]);
	free(hashes[1]);
	free(hashes[2]);
	free(Pubx[0]);
	free(Pubx[1]);
	free(Pubx[2]);
	free(Puby[0]);
	free(Puby[1]);
	free(Puby[2]);
	free(R[0]);
	free(R[1]);
	free(R[2]);
	free(s[0]);
	free(s[1]);
	free(s[2]);

	return 0;
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3]) {
	z z;
	memcpy(z.ke, keys[e], 16);
	memcpy(z.ke1, keys[(e + 1) % 3], 16);
	z.ve = views[e];
	z.ve1 = views[(e + 1) % 3];
	memcpy(z.re, rs[e],4);
	memcpy(z.re1, rs[(e + 1) % 3],4);

	return z;
}



int main(int argc, char * argv[]) {
	setbuf(stdout, NULL);
	srand((unsigned) time(NULL));
	init_EVP();
	openmp_thread_setup();
	unsigned char tbs[MSG_SIZE]; 
	unsigned char r[MSG_SIZE]; 
	char prek[BLOCK_SIZE]; //447 bits = 55.875 bytes

	int i;

	//
        if (argc != 5)
        {
                printf("Usage: %s <number of rounds (e.g. 20, 40, 60, 80, 100)> <to be signed (Hex 64 char)> <secret random r (Hex 64 char)> <preimage (Max 55 char)\n",argv[0]);
                return -1;
        }

        NUM_ROUNDS = atoi(argv[1]);

	unsigned char garbage[4];
	if(RAND_bytes(garbage, 4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	
	hexToBin32(argv[2],tbs);
	hexToBin32(argv[3],r);

	memset(prek,0,sizeof(prek));
	strncpy(prek,argv[4],55);
	
	printf("Iterations of SHA: %d\n", NUM_ROUNDS);
	i = strlen(prek);
	unsigned char input[BLOCK_SIZE];
	memset(input,0,sizeof(input));
	for(int j = 0; j<i; j++) {
		input[j] = prek[j];
	}

	struct timeval begin, delta;
	gettimeofday(&begin,NULL);
	unsigned char rs[NUM_ROUNDS][3][4];
	unsigned char keys[NUM_ROUNDS][3][16];
	a as[NUM_ROUNDS];
	View localViews[NUM_ROUNDS][3];
	int totalCrypto = 0;
	z* zs;
	
for(int loops=0;loops<numLoops;loops++)
{
	//Generating keys
	if(RAND_bytes((unsigned char *) keys, NUM_ROUNDS*3*16) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	if(RAND_bytes((unsigned char *)rs, NUM_ROUNDS*3*4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	

	//Sharing secrets
	unsigned char shares[NUM_ROUNDS][3][i];

	if(RAND_bytes((unsigned char *)shares, NUM_ROUNDS*3*i) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {

		for (int j = 0; j < i; j++) {
			shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
		}

	}

	//Generating randomness
	unsigned char *randomness[NUM_ROUNDS][3];
	#pragma omp parallel for
	for(int k=0; k<(NUM_ROUNDS); k++) {
		for(int j = 0; j<3; j++) {
			randomness[k][j] = malloc(RANDSize*sizeof(unsigned char));
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}

	//Running MPC-SHA2
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) 
	{
		commit(i, shares[k], tbs, r, randomness[k], rs[k], localViews[k], &(as[k]));
		for(int j=0; j<3; j++) {
			free(randomness[k][j]);
		}
	}
	
	//Committing
	#pragma omp parallel for
	for(int k=0; k<(NUM_ROUNDS); k++) {
		unsigned char hash1[SHA256_DIGEST_LENGTH];
		memset(hash1,0,sizeof(hash1));
		H(keys[k][0], localViews[k][0], rs[k][0], hash1);
		memcpy(as[k].h[0], &hash1, 32);
		H(keys[k][1], localViews[k][1], rs[k][1], hash1);
		memcpy(as[k].h[1], &hash1, 32);
		H(keys[k][2], localViews[k][2], rs[k][2], hash1);
		memcpy(as[k].h[2], &hash1, 32);
	}
				
	//Generating E
	int es[NUM_ROUNDS];
	uint32_t finalSig[32];	
	for (int j = 0; j < 32; j++) {
		finalSig[j] = as[0].yp[0][j]^as[0].yp[1][j]^as[0].yp[2][j];
	}

	MP_INT mod;
	mpz_init_set_str(&mod,CURVE_N,16);

	for (int j = 0; j < 1 /*NUM_ROUNDS*/; j++)
	{
		unsigned char bufx[32],bufy[32];
		MP_INT a;
		
		printf("round [%d]:",j);
		ecReconstruct(&(as[j].yp[0][0]),&(as[j].yp[1][0]),&(as[j].yp[2][0]),&(as[j].yp[0][8]),&(as[j].yp[1][8]),&(as[j].yp[2][8]), bufx, bufy);
		printf("pubkey x:");
		for (int i=0;i<32;i++)
			printf("%02x",bufx[i]);
		printf("\npubkey y:");
		for (int i=0;i<32;i++)
			printf("%02x",bufy[i]);
		printf("\n");
	}

	printf("output ECDSA(Challenge) = R:");

	uint32_t tempR;
	for (int j = 16; j < 24; j++) {
		tempR = as[0].yp[0][j]^as[0].yp[1][j]^as[0].yp[2][j];
		printf("%08X",tempR);
	}

	printf("\n");

	{
		unsigned char buf[32];
	
		reconstruct(&(as[0].yp[0][24]),&(as[0].yp[1][24]),&(as[0].yp[2][24]),buf);
		printf("signature :");
		for (int i=0;i<32;i++)
			printf("%02x",buf[i]);
		printf("\n");
	}

	mpz_clear(&mod);
	printf("\n");

	H3(finalSig, as, NUM_ROUNDS, es);

	//Packing Z
	zs = malloc(sizeof(z)*NUM_ROUNDS);

	#pragma omp parallel for
	for(int i = 0; i<(NUM_ROUNDS); i++) {
		zs[i] = prove(es[i],keys[i],rs[i], localViews[i]);
	}
}

	gettimeofday(&delta,NULL);
	unsigned long inMilli = (delta.tv_sec - begin.tv_sec)*1000000 + (delta.tv_usec - begin.tv_usec);
	inMilli /= 1000;
	
	//Writing to file
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "ECDSA%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(as, sizeof(a), NUM_ROUNDS, file);
	fwrite(zs, sizeof(z), NUM_ROUNDS, file);

	fclose(file);

	free(zs);

	printf("Total time taken for %d loops of %d rounds: %d mili-seconds\n",numLoops,NUM_ROUNDS,inMilli);
	printf("Time taken for 1 loops: %d mili-seconds\n",inMilli/numLoops);
	printf("\n");
	printf("Proof output to file %s", outputFile);


	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
