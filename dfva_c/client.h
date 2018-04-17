#include <jsoncpp/json/json.h>
#include <stdio.h>
#include <string.h>
#include "settingsmanager.h"
#include "crypto.h"
using namespace std;

 

class DFVAClient {

	public: 
		DFVAClient();
		Json::Value authenticate(string identification);
		Json::Value autenticate_check(string code);
		bool autenticate_delete(string code);
		Json::Value sign(string identification, string document, string resume, string format);
		Json::Value sign_check(string code);
		bool sign_delete(string code);
		Json::Value validate(string document, string type, string format);
		bool is_suscriptor_connected(string identification, string format);
		void set_algorithm(string new_algorithm);
		
	private:
		string get_timezone();
		string algorithm = "sha512";
		
		Json::Value error_sign_auth_data;
		Json::Value error_validate_data;
		
		AppSettings settings;
		DFVACrypto crypto;
		Json::Value  get_post_params(string enc_parameters);
		string post(char * url, char * data);
		Json::Value parse_json_data(string data, int default_error);
		
};
