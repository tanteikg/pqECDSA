/*

        Name: pqECDSA_verify.c
        Author: Tan Teik Guan
        Description: Verify function for pq resistance for ECDSA using ZKBoo. Modified from MPC_SHA256_VERIFIER.c
*/

/*
 ============================================================================
 Name        : MPC_SHA256_VERIFIER.c
 Author      : Sobuno
 Version     : 0.1
 Description : Verifies a proof for SHA-256 generated by MPC_SHA256.c
 ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "pqECDSA_shared.h"

int NUM_ROUNDS = 100;
int numLoops = 1;

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}

int main(int argc, char * argv[]) {
	setbuf(stdout, NULL);
	init_EVP();
	openmp_thread_setup();
	unsigned char tbs[MSG_SIZE];
	unsigned char r[MSG_SIZE];	
	unsigned char S[MSG_SIZE];	
	int i;
	
        if (argc != 5)
        {
                printf("Usage: %s <number of rounds (e.g. 20, 40, 60, 80, 100)>  <to be signed (Hex 64 char)> <Signature r (Hex 64 char)> <Signature s (Hex 64 char)\n",argv[0]);
                return -1;
        }
        NUM_ROUNDS = atoi(argv[1]);
	hexToBin32(argv[2],tbs);
	hexToBin32(argv[3],r);
	hexToBin32(argv[4],S);

	printf("Iterations of SHA: %d\n", NUM_ROUNDS);
	
	a as[NUM_ROUNDS];
	z zs[NUM_ROUNDS];
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "ECDSA%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "rb");
	if (!file) {
		printf("Unable to open file!");
		return -1;
	}
	fread(&as, sizeof(a), NUM_ROUNDS, file);
	fread(&zs, sizeof(z), NUM_ROUNDS, file);
	fclose(file);

	struct timeval begin, delta;
	gettimeofday(&begin,NULL);

for (int loops=0;loops<numLoops;loops++)
{
	int err = 0;
	uint32_t y[32];

	for (int i = 0; i< 32; i++)
		y[i] = as[0].yp[0][i]^as[0].yp[1][i]^as[0].yp[2][i];

	int es[NUM_ROUNDS*2];
	H3(y,as, NUM_ROUNDS, es);

	 #pragma omp parallel for
	for(int i = 0; i<(NUM_ROUNDS); i++) {
		unsigned char bufx[32],bufy[32];
		MP_INT bigS,bigr;
		MP_INT Pubx,Puby;
		MP_INT bigu1,bigu2;
		MP_INT bigGx, bigGy;
		MP_INT biginvS;
		MP_INT bigH,mod;

		err = 0;
		mpz_init(&bigS);
		mpz_init(&bigr);
		mpz_init(&Pubx);
		mpz_init(&Puby);
	
		ecReconstruct(&(as[i].yp[0][0]),&(as[i].yp[1][0]),&(as[i].yp[2][0]),&(as[i].yp[0][8]),&(as[i].yp[1][8]),&(as[i].yp[2][8]),bufx,bufy);
		mpz_import(&Pubx,32,1,1,0,0,bufx);
		mpz_import(&Puby,32,1,1,0,0,bufy);

		mpz_import(&bigr,8,1,4,0,0,&(as[0].yp[0][16]));
		mpz_import(&bigS,32,1,1,0,0,r);
		if (mpz_cmp(&bigr,&bigS))
		{
			printf("signature r does not match: ");
			mpz_out_str(stdout,16,&bigr);
			printf("vs ");
			mpz_out_str(stdout,16,&bigS);
			printf("\n");
			err |= 1;
		}

		reconstruct(&(as[0].yp[0][24]),&(as[0].yp[1][24]),&(as[0].yp[2][24]),bufx);
		mpz_import(&bigS,32,1,1,0,0,bufx);
	
		for (int i=0; i<32;i++)
		{
			if (bufx[i] != S[i])
			{
				printf("signature S at byte %d [%02X][%02x] does not match\n",i,bufx[i],S[i]);
				err |= 2;
			}
		} 


//		printf("verifying signature for ECDSA(tbs): ");

		mpz_init(&biginvS);
		mpz_init(&bigu1);
		mpz_init(&bigu2);
		mpz_init(&bigH);
		
		mpz_import(&bigH,32,1,1,0,0,tbs);
		mpz_init_set_str(&mod,CURVE_N,16);
		ecInvMod(&biginvS,&bigS,&mod);
		mpz_mul(&bigu1,&bigH,&biginvS);
		mpz_mod(&bigu1,&bigu1,&mod);
		mpz_mul(&bigu2,&bigr,&biginvS);
		mpz_mod(&bigu2,&bigu2,&mod);

		mpz_init_set_str(&bigGx,CURVE_Gx,16);
		mpz_init_set_str(&bigGy,CURVE_Gy,16);

		ecMul(&bigGx,&bigGy,&bigu1);
		ecMul(&Pubx,&Puby,&bigu2);

		ecAddPoint(&bigGx,&bigGy,&Pubx,&Puby);
		mpz_mod(&bigGx,&bigGx,&mod);
		if (mpz_cmp(&bigGx,&bigr))
		{
			printf("invalid r. computed r : ");
			mpz_out_str(stdout,16,&bigGx);
			printf("\n");

			err |= 4;
		}

		if (!err)
		{
			int verifyResult = verify(as[i], es[i], zs[i]);
			if (verifyResult != 0) {
				printf("round [%d] : Not Verified rc = %d\n", i, verifyResult);
			}
			else
			{
				printf("round [%d] ok \n",i);
			}
		}
		else
			printf("round [%d] error code = %d\n",i,err);

		mpz_clear(&biginvS);
		mpz_clear(&bigu1);
		mpz_clear(&bigu2);
		mpz_clear(&bigH);
		mpz_clear(&bigS);
		mpz_clear(&bigr);
		mpz_clear(&Pubx);
		mpz_clear(&Puby);
		mpz_clear(&mod);
		mpz_clear(&bigGx);
		mpz_clear(&bigGy);
	}
}
	
	gettimeofday(&delta,NULL);
	unsigned long inMilli = (delta.tv_sec - begin.tv_sec)*1000000 + (delta.tv_usec - begin.tv_usec);
	inMilli /= 1000;

	printf("Total time for %d loops of %d rounds: %ju miliseconds\n", numLoops,NUM_ROUNDS,(uintmax_t)inMilli);
	printf("Time taken for 1 loops: %ju miliseconds\n", (uintmax_t)inMilli/numLoops);
	
	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
