#include <jsoncpp/json/json.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <string.h>
#include "settingsmanager.h"
using namespace std;

class DFVACrypto {
	public:
		DFVACrypto();
		char * base64encode(const unsigned char *input, int length);
		string base64decode(string);
		string  get_hash_sum(string rdata, string algorithm);
		string  encrypt(string data);
		string  decrypt(string data);
		
	private:
		const int IV_SIZE = 16 ;
		const int TAG_SIZE = 16 ;
		RSA * get_public_key();
		RSA * get_private_key();
		char * get_char_from_str(string data);
		AppSettings settings;
};
