#include <stdio.h>
#include <openssl/bn.h>	


void printBN(char*msg, BIGNUM*a)
{
	char*number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);}


void main()
{	
	
	BN_CTX*ctx = BN_CTX_new();
	BIGNUM* d = BN_new();
	BIGNUM* n = BN_new();
	BIGNUM* e = BN_new();
	BIGNUM* M = BN_new();
	BIGNUM* C = BN_new();

	// Assign d
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign n
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	// Assign e
	BN_hex2bn(&e, "010001");

	//Assign the message - A top secret!
	BN_hex2bn(&M, "4120746f702073656372657421");
	
	//Encrypt the message
	BN_mod_exp(C, M, e, n, ctx);

	printBN("d is: ", d);
	printBN("e is: ", e);
	printBN("n is: ", n);	
	printBN("M is: ", M);
	printf("-------------------------------------\n");
	printBN("The Ciphertext is: ", C);

}
