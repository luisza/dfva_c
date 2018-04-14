#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <iomanip>
#include <cstdlib>
#include "settingsmanager.h"

using namespace std;
/// http://emocias.blogspot.com/2011/06/libconfig-cc-configuration-file-library.html
SettingsManager::SettingsManager(){
	

		

}

char * SettingsManager::get_config_filename(){
	filename = ".dfva_c_client.conf";
	if ( (homedir = getenv("XDG_CONFIG_HOME")) == NULL )
		if((homedir = getenv("HOME")) == NULL) {
			homedir = getpwuid(getuid())->pw_dir;
		}
		
	string filenames  = (string)homedir + "/" + (string)filename; 
	strcpy(settings_filename, filenames.c_str());
	return  settings_filename;
}
AppSettings SettingsManager::load_settings_from_file(){
	  AppSettings appsettings;
	  try
	  {
		appsettings=this->_load_settings_from_file();

	  }
	  catch(const FileIOException &fioex)
	  {
		 appsettings= AppSettings();
		 this->save(appsettings);
	  }	
	return appsettings;
}

AppSettings SettingsManager::_load_settings_from_file(){
	 AppSettings appsettings;
	 cfg.readFile(get_config_filename());	
	 const Setting& root = cfg.getRoot();
	 const Setting &general= root["general"] ;
	 const Setting &dfva= root["DFVA"] ;
	 const Setting &institution= root["institution"] ;
	 const Setting &signformat = root["DFVA"]["SUPPORTED_SIGN_FORMAT"];
	 const Setting &validateformat = root["DFVA"]["SUPPORTED_VALIDATE_FORMAT"];
	 
	 general.lookupValue("TIMEZONE", appsettings.TIMEZONE);
	 
	dfva.lookupValue("ALGORITHM", appsettings.ALGORITHM);
	dfva.lookupValue("DFVA_SERVER_URL", appsettings.DFVA_SERVER_URL);
	dfva.lookupValue("AUTHENTICATE_INSTITUTION", appsettings.AUTHENTICATE_INSTITUTION);
	dfva.lookupValue("CHECK_AUTHENTICATE_INSTITUTION",  appsettings.CHECK_AUTHENTICATE_INSTITUTION);
	dfva.lookupValue("AUTHENTICATE_DELETE",  appsettings.AUTHENTICATE_DELETE);
	dfva.lookupValue("SIGN_INSTUTION",  appsettings.SIGN_INSTUTION);
	dfva.lookupValue("CHECK_SIGN_INSTITUTION",  appsettings.CHECK_SIGN_INSTITUTION);
	dfva.lookupValue("SIGN_DELETE",   appsettings.SIGN_DELETE);
	dfva.lookupValue("VALIDATE_CERTIFICATE",   appsettings.VALIDATE_CERTIFICATE);
	dfva.lookupValue("VALIDATE_DOCUMENT",   appsettings.VALIDATE_DOCUMENT);
	dfva.lookupValue("SUSCRIPTOR_CONNECTED", appsettings.SUSCRIPTOR_CONNECTED); 	


	for(int i=0; i<signformat.getLength() && i<SIGN_FORMAT_LEN; i++){
		strcpy(appsettings.SUPPORTED_SIGN_FORMAT[i], signformat[i].c_str());
		appsettings.max_sign_format=i; 
		 
	}

	for(int i=0; i<validateformat.getLength() && i<VALIDATE_FORMAT_LEN; i++){
		strcpy(appsettings.SUPPORTED_VALIDATE_FORMAT[i], validateformat[i].c_str());
		appsettings.max_validate_format=i;
	}
	
	institution.lookupValue("SERVER_PUBLIC_KEY", appsettings.SERVER_PUBLIC_KEY);
	institution.lookupValue("PUBLIC_CERTIFICATE", appsettings.PUBLIC_CERTIFICATE);
	institution.lookupValue("CODE", appsettings.CODE);
	institution.lookupValue("PRIVATE_KEY", appsettings.PRIVATE_KEY);
	institution.lookupValue("URL_NOTIFY",  appsettings.URL_NOTIFY); 
	return appsettings;
}

int SettingsManager::save(AppSettings appsettings){
	Setting &root = cfg.getRoot();
	Setting &general = root.add("general", Setting::TypeGroup);
	Setting &dfva= root.add("DFVA", Setting::TypeGroup);
	Setting &institution = root.add("institution", Setting::TypeGroup);

	
	general.add("TIMEZONE", Setting::TypeString) = appsettings.TIMEZONE;
	
	dfva.add("ALGORITHM", Setting::TypeString) = appsettings.ALGORITHM;
	dfva.add("DFVA_SERVER_URL", Setting::TypeString) = appsettings.DFVA_SERVER_URL;
	dfva.add("AUTHENTICATE_INSTITUTION", Setting::TypeString) = appsettings.AUTHENTICATE_INSTITUTION;
	dfva.add("CHECK_AUTHENTICATE_INSTITUTION", Setting::TypeString) = appsettings.CHECK_AUTHENTICATE_INSTITUTION;
	dfva.add("AUTHENTICATE_DELETE", Setting::TypeString) = appsettings.AUTHENTICATE_DELETE;
	dfva.add("SIGN_INSTUTION", Setting::TypeString) = appsettings.SIGN_INSTUTION;
	dfva.add("CHECK_SIGN_INSTITUTION", Setting::TypeString) = appsettings.CHECK_SIGN_INSTITUTION;
	dfva.add("SIGN_DELETE", Setting::TypeString) = appsettings.SIGN_DELETE;
	dfva.add("VALIDATE_CERTIFICATE", Setting::TypeString) = appsettings.VALIDATE_CERTIFICATE;
	dfva.add("VALIDATE_DOCUMENT", Setting::TypeString) = appsettings.VALIDATE_DOCUMENT;
	dfva.add("SUSCRIPTOR_CONNECTED", Setting::TypeString) = appsettings.SUSCRIPTOR_CONNECTED;
	
	
	Setting &SUPPORTED_SIGN_FORMAT = dfva.add("SUPPORTED_SIGN_FORMAT", Setting::TypeArray);
	Setting &SUPPORTED_VALIDATE_FORMAT = dfva.add("SUPPORTED_VALIDATE_FORMAT", Setting::TypeArray);

	 for(int i = 0; i < appsettings.max_sign_format && i < SIGN_FORMAT_LEN; ++i){
		 SUPPORTED_SIGN_FORMAT.add(Setting::TypeString) = appsettings.SUPPORTED_SIGN_FORMAT[i];
	 }
	 for(int i = 0; i < appsettings.max_validate_format && i < VALIDATE_FORMAT_LEN; ++i){
		 SUPPORTED_VALIDATE_FORMAT.add(Setting::TypeString) = appsettings.SUPPORTED_VALIDATE_FORMAT[i];
	 }
	institution.add("SERVER_PUBLIC_KEY", Setting::TypeString) = appsettings.SERVER_PUBLIC_KEY;
	institution.add("PUBLIC_CERTIFICATE", Setting::TypeString) = appsettings.PUBLIC_CERTIFICATE;
	institution.add("CODE", Setting::TypeString) = appsettings.CODE;
	institution.add("PRIVATE_KEY", Setting::TypeString) = appsettings.PRIVATE_KEY;
	institution.add("URL_NOTIFY", Setting::TypeString) = appsettings.URL_NOTIFY;

	char * output_file = get_config_filename();

	  try
	  {
		cfg.writeFile(output_file);

	  }
	  catch(const FileIOException &fioex)
	  {
		cerr << "I/O error while writing file: " << output_file << endl;
		return(EXIT_FAILURE);
	  }

	  return(EXIT_SUCCESS);
}

