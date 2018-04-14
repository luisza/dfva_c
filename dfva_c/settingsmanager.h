#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <libconfig.h++>

using namespace std;
using namespace libconfig;

const int SIGN_FORMAT_LEN = 10;
const int VALIDATE_FORMAT_LEN = 10;
const int MAX_FILENAME_SIZE = 1000;

class AppSettings{
	public: 
		string TIMEZONE = "America/Costa_Rica";
		string ALGORITHM = "sha512";
		string DFVA_SERVER_URL = "http://localhost:8000";
		string AUTHENTICATE_INSTITUTION = "/authenticate/institution/";
		string CHECK_AUTHENTICATE_INSTITUTION = "/authenticate/%s/institution_show/";
		string AUTHENTICATE_DELETE = "/authenticate/%s/institution_delete/";
		string SIGN_INSTUTION = "/sign/institution/";
		string CHECK_SIGN_INSTITUTION = "/sign/%s/institution_show/";
		string SIGN_DELETE = "/sign/%s/institution_delete/";
		string VALIDATE_CERTIFICATE = "/validate/institution_certificate/";
		string VALIDATE_DOCUMENT = "/validate/institution_document/";
		string SUSCRIPTOR_CONNECTED = "/validate/institution_suscriptor_connected/";


	
		char SUPPORTED_SIGN_FORMAT[SIGN_FORMAT_LEN][30]= {"xml_cofirma", "xml_contrafirma", "odf", "msoffice"};
		char SUPPORTED_VALIDATE_FORMAT[VALIDATE_FORMAT_LEN][30] = {"certificate", "cofirma", "contrafirma", "odf", "msoffice"};
		int max_sign_format = 4;
		int max_validate_format = 5;

		string SERVER_PUBLIC_KEY="";
		string PUBLIC_CERTIFICATE="";
		string CODE="";
		string PRIVATE_KEY="";
		string URL_NOTIFY="N/D";
		
	
};

class SettingsManager{

	public:
		SettingsManager();
		AppSettings  load_settings_from_file();
		int save(AppSettings appsettings);

	private:
		 Config cfg;
		 const char * homedir;
		 const char * filename;
		 char settings_filename[MAX_FILENAME_SIZE];
		 char * get_config_filename();
		 AppSettings _load_settings_from_file();
};
