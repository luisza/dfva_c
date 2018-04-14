#include <jsoncpp/json/json.h>
#include <stdio.h>
#include <string.h>
#include "settingsmanager.h"
using namespace std;

 

class DFVAClient {

	public: 
		DFVAClient();
		Json::Value authenticate(string identification);
		Json::Value check_autenticate(string code);
		bool autenticate_delete(string code);
		Json::Value sign(string identification, string document, string resume, string format);
		Json::Value check_sign(string code);
		bool sign_delete(string code);
		Json::Value validate(string document, string type, string format);
		bool is_suscriptor_connected(string identification, string format);
		void set_algorithm(string new_algorithm);
		
	private:
		string get_timezone();
		string algorithm = "sha512";
		AppSettings settings;
};
