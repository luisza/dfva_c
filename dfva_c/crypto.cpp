#include <openssl/sha.h>
#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
using namespace std;

DFVACrypto::DFVACrypto(){}

char * DFVACrypto::base64encode(const unsigned char *input, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;
 
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
 
  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;
 
  BIO_free_all(b64);
 
  return buff;
}

 
char * DFVACrypto::base64decode(unsigned char *input, int length)
{
  BIO *b64, *bmem;
 
  char *buffer = (char *)malloc(length);
  memset(buffer, 0, length);
 
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);
 
  BIO_read(bmem, buffer, length);
 
  BIO_free_all(bmem);
 
  return buffer;
}

string  DFVACrypto::get_hash_sum(string rdata, string algorithm){ 
	const char * data = rdata.c_str();
	string dev;
	 
	if(algorithm=="sha256"){
		unsigned char digest[SHA256_DIGEST_LENGTH];
		SHA256(reinterpret_cast<const unsigned char *>(data), 
				strlen(data), digest);
	    char mdString[SHA256_DIGEST_LENGTH*2+1];
	 
		for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			 sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
		dev=string(mdString);
	}else if(algorithm=="sha384"){
		unsigned char digest[SHA384_DIGEST_LENGTH];
		SHA384(reinterpret_cast<const unsigned char *>(data), 
				strlen(data), (unsigned char*)&digest);
	    char mdString[SHA384_DIGEST_LENGTH*2+1];
	 
		for(int i = 0; i < SHA384_DIGEST_LENGTH; i++)
			 sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
		dev=string(mdString);		
	}else if(algorithm=="sha512"){
		unsigned char digest[SHA512_DIGEST_LENGTH];
		SHA512(reinterpret_cast<const unsigned char *>(data), 
						strlen(data),(unsigned char*)&digest);
	    char mdString[SHA512_DIGEST_LENGTH*2+1];
	 
		for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
			 sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
		dev=string(mdString);		
	}

	return dev;
}
string  DFVACrypto::encrypt(string data){ return data;}
string  DFVACrypto::decrypt(string data){ return data;}
