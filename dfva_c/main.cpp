
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
	DFVAClient client;
	Json::Value value = client.authenticate("402120119");
	value = client.autenticate_check(value["id_transaction"].asString());
	
/**	
	string data = value.toStyledString(); 
	char * vdata = new char [data.length()+1];
	strcpy (vdata, data.c_str());
	cout << string(vdata) << endl;
	char * b64=crypto.base64encode(reinterpret_cast<unsigned char *>(vdata), strlen(vdata));
	cout <<  string(b64) << endl << endl ;
	cout << crypto.get_hash_sum(value.toStyledString(), "sha384") << endl;


	string data = "a13UJIqTDN4NSfq5quezYE+vRbRj1pTf2BgNRYbiReyyCykez3sDfKI0WRPmU3cudTP5ADlg/tAwMXKLoEdr6Up5tj2ptA+aA9uneGQqWWZO1/j3spZ3FuyOSyV4WoVhdem9QW6M2JpvMnMy5TbgtsImY6TUWyC65pnudMvA1CCUIltb/7fD1gnZjVshipdD04NflEyX14Sm9JeJDEPmqD4fsnSyRuUg2ax6HCh3KndlKRiauY3xYsirvVYzq37+EgWxupyr/az5E6XOxBie184v3WVGN7wZCAO+SPW5LXi0nWnlRIs1M95s0Ui7JSs1cx1WTDMcR/bJCcjRwr6gILB4+QWzmezbkWDsjvbpX94v4keh3+zUD+HD1En8en7bh+Jei9bUHko5uQ==";
	**/
	
	/**
	string data="aG9sYSBtdW5kbw==";
	cout << crypto.base64decode( data) << endl;

	cout << crypto.decrypt(data) << endl;
	**/
}

