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
		Json::Value validate(string document, string format);
		bool is_suscriptor_connected(string identification);
		
	private:
		string get_timezone();
		Json::Value  get_post_params(string enc_parameters);
		string post(char * url, char * data);
		string _post(char * url, char * data);
		Json::Value get_default_error(int defualt_error);
		
	protected:
		
		Json::Value error_sign_auth_data;
		Json::Value error_validate_data;
		Json::Value error_delete;
		Json::Value parse_json_data(string data, int default_error, bool check_connected);
				
		AppSettings settings;
		DFVACrypto crypto;
	
};
