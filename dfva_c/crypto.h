#include <jsoncpp/json/json.h>
#include <stdio.h>
#include <string.h>

using namespace std;

class DFVACrypto {
	public:
		DFVACrypto();
		char * base64encode(const unsigned char *input, int length);
		char * base64decode(unsigned char *input, int length);
		string  get_hash_sum(string rdata, string algorithm);
		string  encrypt(string data);
		string  decrypt(string data);
};
