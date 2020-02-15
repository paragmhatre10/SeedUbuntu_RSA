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
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *z = BN_new();
	BIGNUM *FYofN = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
	
	// Assign p
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	
	// Assign q
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	
	// Assign e
	BN_hex2bn(&e, "0D88C3");

	//Assign z as 1
	BN_dec2bn(&z, "1");

	//Calculate (p-1)
	BN_sub(x, p, z);
	
	//Calculate (q-1)
	BN_sub(y, q, z);

	//Calculate FYofN = (p-1)*(q-1)
	BN_mul(FYofN, x, y, ctx);

	//Calculate d or the private key using the below function
	BN_mod_inverse(d, e, FYofN, ctx);


	printBN("P is",p);
	printBN("P-1 is",x);
	printBN("Q is",q);
	printBN("Q-1 is",y);
	printBN("FY of N is",FYofN);
	printf("-------------------------------------\n");
	printBN("The private key is",d);	


}
