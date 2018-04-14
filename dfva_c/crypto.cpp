#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h> 
#include <cryptopp/cryptlib.h> 
#include <cryptopp/aes.h> 
#include <cryptopp/eax.h> 
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

#include "crypto.h"

#define SESSION_KEY_SIZE 16

using namespace std;

using CryptoPP::AES;
using CryptoPP::EAX;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

DFVACrypto::DFVACrypto(){
	SettingsManager settingsManager;
	settings=settingsManager.load_settings_from_file();
}

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



RSA * DFVACrypto::get_public_key(){

	char * vkey = new char [this->settings.SERVER_PUBLIC_KEY.length()+1];
	strcpy (vkey, this->settings.SERVER_PUBLIC_KEY.c_str());
	unsigned char * key = reinterpret_cast<unsigned char *>(vkey);
	
	RSA *rsa= NULL;
	BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    return rsa;
}
RSA * DFVACrypto::get_private_key(){

	char * vkey = new char [this->settings.PRIVATE_KEY.length()+1];
	strcpy (vkey, this->settings.PRIVATE_KEY.c_str());
	unsigned char * key = reinterpret_cast<unsigned char *>(vkey);

	RSA *rsa= NULL;
	BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    
    return rsa;
}

string  DFVACrypto::encrypt(string data){ 
	string ciphertext;
	char * vdata = new char [data.length()+1];
	strcpy (vdata, data.c_str());
	
	unsigned char session_key[SESSION_KEY_SIZE];
	RAND_bytes(session_key, sizeof(session_key));
	
	int data_len=strlen(vdata);
	
    RSA * pub_key = this->get_public_key();
    char *session_key_enc = (char *)malloc(RSA_size(pub_key));
    int result = RSA_public_encrypt(data_len, 
					session_key, 
					reinterpret_cast<unsigned char *>(session_key_enc),
					pub_key,  
					RSA_PKCS1_OAEP_PADDING);
					
	// AES EAX mode
	AutoSeededRandomPool rng;
	EAX< AES >::Encryption enc;
	byte iv[ AES::BLOCKSIZE * 16 ];
    rng.GenerateBlock( iv, sizeof(iv) );
    
    enc.SetKeyWithIV( session_key, sizeof(session_key), iv, sizeof(iv) );

	StringSource ss( data, true,
		new AuthenticatedEncryptionFilter( enc,
			new StringSink( ciphertext )
		) // AuthenticatedEncryptionFilter
	); // StringSource

	return ciphertext;
}
string  DFVACrypto::decrypt(string data){ return data;}
