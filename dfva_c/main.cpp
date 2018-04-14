
#include <stdio.h>
#include <cstring>
//#include <settingsmanager.h>
#include <client.h>
#include <jsoncpp/json/json.h>
using namespace std;

#include "crypto.h"



int main( int argc, const char* argv[] )
{
	/**
	SettingsManager settings;
	
	
	AppSettings appsettings = settings.load_settings_from_file();
	
	for(int i=0; i<SIGN_FORMAT_LEN; i++){
		cout << "Leido: "<< appsettings.SUPPORTED_SIGN_FORMAT[i] << endl;
	}
	
	cout << "Leido: "<< appsettings.SERVER_PUBLIC_KEY << " -- " << appsettings.PUBLIC_CERTIFICATE << endl;
	*/
	/**
	AppSettings appsettings;
	settings.save(appsettings);
	**/

	DFVACrypto crypto;
/**	DFVAClient client;
	Json::Value value = client.authenticate("402120119");
	string data = value.toStyledString(); 
	char * vdata = new char [data.length()+1];
	strcpy (vdata, data.c_str());
	cout << string(vdata) << endl;
	char * b64=crypto.base64encode(reinterpret_cast<unsigned char *>(vdata), strlen(vdata));
	cout <<  string(b64) << endl << endl ;
	cout << crypto.get_hash_sum(value.toStyledString(), "sha384") << endl;
**/
	cout << crypto.encrypt("Hola mundo") << endl;
}

