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
	BIGNUM* M1 = BN_new();
	BIGNUM* M2 = BN_new();
	BIGNUM* S1 = BN_new();
	BIGNUM* S2 = BN_new();

	// Assign d
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign n
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	// Assign e
	BN_hex2bn(&e, "010001");

	//Assign message 1
	BN_hex2bn(&M1, "49206f776520796f752024323030302e");

	//Sign message 1
	BN_mod_exp(S1, M1, d, n, ctx);

	//Assign message 2
	BN_hex2bn(&M2, "49206f776520796f752024333030302e");
	
	//Sign the message
	BN_mod_exp(S2, M2, d, n, ctx);

	printBN("d is: ", d);
	printBN("e is: ", e);
	printBN("n is: ", n);	
	printf("-------------------------------------\n");	
	printBN("Original message is: ",M1);
	printBN("The Signature is: ",S1);
	printBN("Modified message is: ",M2);
	printBN("The Signature is: ",S2);
	

}
