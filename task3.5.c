#include <stdio.h>
#include <openssl/bn.h>	


void printBN(char*msg, BIGNUM*a)
{
	char*number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);}


void main()
{	
	
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *M = BN_new();
	BIGNUM *S1 = BN_new();
	BIGNUM *S2 = BN_new();
	BIGNUM *D_S1 = BN_new();
	BIGNUM *D_S2 = BN_new();

	// Assign n
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

	// Assign e
	BN_hex2bn(&e, "010001");

	//Assign message
	BN_hex2bn(&M, "4c61756e63682061206d6973736c652e");

	//Assign signature 1
	BN_hex2bn(&S1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

	//Decrypt signature 1
	BN_mod_exp(D_S1, S1, e, n, ctx);

	//Assign signature 2 (corrupted)
	BN_hex2bn(&S2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	
	//Decrypt signature 2 (corrupted)
	BN_mod_exp(D_S2, S2, e, n, ctx);

	printBN("e is: ", e);
	printBN("n is: ", n);	
	printf("-------------------------------------\n");	
	printBN("Original decrypted signature is: ",D_S1);
	printBN("The corrupted decrypted signature is: ",D_S2);
	

}
