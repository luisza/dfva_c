#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <iostream> 
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
#include <cryptopp/base64.h> 
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
using CryptoPP::Exception;
using CryptoPP::Base64Decoder;


// https://stackoverflow.com/questions/20967964/crypto-symmetric-algorithms-and-authenticated-block-modes-combinations

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

 
string DFVACrypto::base64decode(string encoded)
{
	string decoded;
	Base64Decoder decoder;
	decoder.Attach( new StringSink( decoded ) );

	decoder.Put( (byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();
	return decoded;
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

char * DFVACrypto::get_char_from_str(string data){
	char * vdata = new char [data.length()+1];
	strcpy (vdata, data.c_str());
	return vdata;
}

string  DFVACrypto::encrypt(string data){ 

	size_t n = (size_t)-1;
	int total_size = 0;
	std::string cipher_text;
	
	unsigned char session_key[SESSION_KEY_SIZE];
	RAND_bytes(session_key, sizeof(session_key));
	
	
    RSA * pub_key = this->get_public_key();
    unsigned char * session_key_enc = (unsigned char *)malloc(RSA_size(pub_key));
    
    int enc_size = RSA_public_encrypt(SESSION_KEY_SIZE, 
					session_key, 
					session_key_enc,
					pub_key,  
					RSA_PKCS1_OAEP_PADDING);
	total_size= enc_size;
	 
	// AES EAX mode
	AutoSeededRandomPool rng;
	EAX< AES >::Encryption enc;

	byte iv[ IV_SIZE ];
    rng.GenerateBlock( iv, IV_SIZE);
    enc.SetKeyWithIV( session_key, SESSION_KEY_SIZE, iv, IV_SIZE );
	
	total_size += IV_SIZE ;
 
	CryptoPP::StringSink *string_sink = new CryptoPP::StringSink(cipher_text);
	// The AuthenticatedEncryptionFilter adds padding as required.
	  CryptoPP::BufferedTransformation *transformator = NULL;
	  transformator = new CryptoPP::AuthenticatedEncryptionFilter(
		  enc,
		  string_sink);

	  CryptoPP::StringSource(
		  data,
		  true,
		  transformator);


	unsigned char * ciphertext=(unsigned char *)cipher_text.c_str();
	n=cipher_text.size();
	total_size += n;
	byte enc_data[total_size];
		
	memcpy(enc_data, session_key_enc, enc_size);
	memcpy(enc_data + enc_size, iv, IV_SIZE);
	memcpy(enc_data + enc_size+IV_SIZE,  ciphertext + (n-TAG_SIZE), TAG_SIZE);
	memcpy(enc_data + enc_size+IV_SIZE+TAG_SIZE, ciphertext, n-TAG_SIZE );
	
	//char * b64=this->get_char_from_str(enc_data);
	return base64encode((unsigned char *)enc_data, total_size);
}
string  DFVACrypto::decrypt(string data){ 
	string recovered_plain_text;

	string bstring = this->base64decode( data);
	RSA * priv_key = this->get_private_key();
	int key_enc_len = RSA_size(priv_key);
	
	string enc_session = bstring.substr( 0, key_enc_len);
	string iv = bstring.substr( key_enc_len, IV_SIZE);
	string tag = bstring.substr( key_enc_len+IV_SIZE, TAG_SIZE);
	string enc_message = bstring.substr( key_enc_len+IV_SIZE+TAG_SIZE, bstring.size());
	string ciphertext = enc_message + tag;
/**	
	cout << "enc session key: " << string(this->base64encode((unsigned char*)enc_session.c_str(), key_enc_len)) << endl;
	cout << "IV: " << this->base64encode((unsigned char *)iv.c_str(), IV_SIZE) << endl;
	cout << "TAG: " << this->base64encode((unsigned char *)tag.c_str(), TAG_SIZE) << endl;	
**/
	unsigned char session_key[32];
	
	int  session_key_len = RSA_private_decrypt(key_enc_len, 
			(unsigned char*)enc_session.c_str(),
			session_key,
			priv_key, 
			RSA_PKCS1_OAEP_PADDING);	

//	cout << "session key: " << this->base64encode(session_key, session_key_len) << endl;
	
	
	EAX< AES >::Decryption decryption;
	  decryption.SetKeyWithIV(
      (byte *)session_key, session_key_len,
      (byte *)iv.c_str());
	
	CryptoPP::StringSink *string_sink = new CryptoPP::StringSink(
	  recovered_plain_text);
	CryptoPP::BufferedTransformation *transformator = NULL;
	CryptoPP::AuthenticatedDecryptionFilter *decryption_filter = NULL;

	decryption_filter = new CryptoPP::AuthenticatedDecryptionFilter(
	  decryption,
	  string_sink);
	transformator = new CryptoPP::Redirector(*decryption_filter);

	CryptoPP::StringSource(
	  ciphertext,
	  true,
	  transformator);
	return recovered_plain_text;
}
