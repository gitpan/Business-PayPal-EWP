#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"
#include "openssl/buffer.h"
#include "openssl/bio.h"
#include "openssl/sha.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/pkcs7.h"
#include "openssl/pem.h"

/* The following code comes directly from PayPal's ButtonEncyption.cpp file, and has been
   modified only to work with C
*/

char* sign_and_encrypt(const char *data, RSA *rsa, X509 *x509, X509 *PPx509, bool verbose)
{
	char *ret;
	EVP_PKEY *pkey;
	PKCS7 *p7;
	BIO *memBio;
	BIO *p7bio;
	BIO *bio;
	PKCS7_SIGNER_INFO* si;
	int len;
	char *str;

	pkey = EVP_PKEY_new();

	if (EVP_PKEY_set1_RSA(pkey, rsa) == 0)
	{
		printf("Fatal Error: Unable to create EVP_KEY from RSA key\n");
		goto end;
	} else if (verbose) {
		printf("Successfully created EVP_KEY from RSA key\n");
	}

	// Create a signed and enveloped PKCS7
	p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped);

	si = PKCS7_add_signature(p7, x509, pkey, EVP_sha1());

	if (si) {
		if (PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
			OBJ_nid2obj(NID_pkcs7_data)) <= 0)
		{
			printf("Fatal Error: Unable to add signed attribute to certificate\n");
			printf("OpenSSL Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto end;
		} else if (verbose) {
			printf("Successfully added signed attribute to certificate\n");
		}

	} else {
		printf("Fatal Error: Failed to sign PKCS7\n");
		goto end;
	}

	//Encryption
	if (PKCS7_set_cipher(p7, EVP_des_ede3_cbc()) <= 0)
	{
		printf("Fatal Error: Failed to set encryption algorithm\n");
		printf("OpenSSL Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto end;
	} else if (verbose) {
		printf("Successfully added encryption algorithm\n");
	}

	if (PKCS7_add_recipient(p7, PPx509) <= 0)
	{
		printf("Fatal Error: Failed to add PKCS7 recipient\n");
		printf("OpenSSL Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto end;
	} else if (verbose) {
		printf("Successfully added recipient\n");
	}

	if (PKCS7_add_certificate(p7, x509) <= 0)
	{
		printf("Fatal Error: Failed to add PKCS7 certificate\n");
		printf("OpenSSL Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto end;
	} else if (verbose) {
		printf("Successfully added certificate\n");
	}

	memBio = BIO_new(BIO_s_mem());
	p7bio = PKCS7_dataInit(p7, memBio);

	if (!p7bio) {
		printf("OpenSSL Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	//Pump data to special PKCS7 BIO. This encrypts and signs it.
	BIO_write(p7bio, data, strlen(data));
	BIO_flush(p7bio);
	PKCS7_dataFinal(p7, p7bio);

	//Write PEM encoded PKCS7
	bio = BIO_new(BIO_s_mem());

	if (!bio || (PEM_write_bio_PKCS7(bio, p7) == 0))
	{
		printf("Fatal Error: Failed to create PKCS7 PEM\n");
	} else if (verbose) {
		printf("Successfully created PKCS7 PEM\n");
	}

	BIO_flush(bio);
	len = BIO_get_mem_data(bio, &str);
	Newz(1,ret,sizeof(char)*(len+1),char);
	memcpy(ret, str, len);
	ret[len] = 0;

end:
	//Free everything
	if (p7)
		PKCS7_free(p7);
	if (bio)
		BIO_free_all(bio);
	if (memBio)
		BIO_free_all(memBio);
	if (p7bio)
		BIO_free_all(p7bio);
	if (pkey)
		EVP_PKEY_free(pkey);
	return ret;
}

MODULE = Business::PayPal::EWP		PACKAGE = Business::PayPal::EWP
PROTOTYPES: DISABLE

void
OpenSSL_add_all_algorithms()

void
BIO_free_all(bio)
    BIO* bio

X509*
PEM_read_bio_X509(bp,x,cb,u)
    BIO* bp
    void* x
    char* cb
    void* u

RSA*
PEM_read_bio_RSAPrivateKey(bp,x,cb,u)
    BIO* bp
    void* x
    char* cb
    void* u

char *
sign_and_encrypt(data,rsa,x509,PPx509,verbose)
    const char* data
    RSA* rsa
    X509* x509
    X509* PPx509
    bool verbose
