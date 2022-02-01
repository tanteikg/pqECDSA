TARGETS : pqECDSA_prove.exe pqECDSA_verify.exe

pqECDSA_prove.exe : pqECDSA_prove.c pqECDSA_shared.h
	gcc -O2 -Wl,--stack,16777216 -fopenmp pqECDSA_prove.c -o pqECDSA_prove.exe -lssl -lcrypto -lgmp

pqECDSA_verify.exe : pqECDSA_verify.c pqECDSA_shared.h
	gcc -O2 -Wl,--stack,16777216 -fopenmp pqECDSA_verify.c -o pqECDSA_verify.exe -lssl -lcrypto -lgmp

clean :
	rm  pqECDSA_prove.exe pqECDSA_verify.exe *.stackdump *.bin


