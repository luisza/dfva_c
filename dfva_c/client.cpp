#include <iostream>
#include <exception>

#include "client.h"
#include <jsoncpp/json/json.h>
#include <curl/curl.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#define SIGN_AUTH_ERROR 1
#define VALIDATE_ERROR 2
#define SIGN_AUTH_DELETE 3
#define HASHSUM_ERROR 4

using namespace std;
using namespace Json;

#define SIGNFORMATSTR  5
#define VALIDATEFORMATSTR 6

const string SignFormatStr[] = {
      "xml_cofirma",
      "xml_contrafirma",
      "odf",
      "msoffice",
      "pdf"
};

const string ValidateFormatStr[]{
	"certificate", 
	"cofirma", 
	"contrafirma", 
	"odf", 
	"msoffice",
	"pdf"
};


bool check_if_exists(const string data[], int size, string compare){
   for(int x=0; x<size; x++){
		if(compare.compare(data[x]) == 0) return true;
   }
  return false;
}

DFVAClient::DFVAClient(){
	SettingsManager settingsManager;
	settings=settingsManager.load_settings_from_file();
	
	error_sign_auth_data["code"]= "N/D";
	error_sign_auth_data["status"]= 2;
	error_sign_auth_data["identification"]= 0;
	error_sign_auth_data["id_transaction"]= 0;
	error_sign_auth_data["request_datetime"]= "";
	error_sign_auth_data["sign_document"] = "";
	error_sign_auth_data["expiration_datetime"]= "";
	error_sign_auth_data["received_notification"]= true;
	error_sign_auth_data["duration"]= 0;
	error_sign_auth_data["status_text"]= "Problema de comunicación interna";
	
	
	error_validate_data["code"] = "N/D";
	error_validate_data["status"]= 2;
	error_validate_data["identification"] = 0;
	error_validate_data["received_notification"] = 0;
    error_validate_data["status_text"] = "Problema de comunicación interna";
    
    
    error_hashsum_data["code"] = "N/D";
	error_hashsum_data["status"]= -2;
	error_hashsum_data["identification"] = 0;
	error_hashsum_data["received_notification"] = 0;
    error_hashsum_data["status_text"] = "Problema al calcular sumas hash, son diferentes";
    
    error_delete["result"] = false;
		
}


Json::Value  DFVAClient::get_post_params(string enc_parameters){
	string edata = this->crypto.encrypt(enc_parameters);
	string hashsum = this->crypto.get_hash_sum(edata, settings.ALGORITHM);
	Json::Value params;

	params["data_hash"]= hashsum;
	params["algorithm"]= settings.ALGORITHM;
	params["public_certificate"]= settings.PUBLIC_CERTIFICATE;
	params["institution"]= settings.CODE;
	params["data"]= edata;
	  
	return params;
}

Json::Value DFVAClient::get_default_error(int default_error){
	
	switch(default_error){
		case SIGN_AUTH_ERROR:
			return error_sign_auth_data;
		case VALIDATE_ERROR:
			return error_validate_data;
		case SIGN_AUTH_DELETE:
			return error_delete;
		case HASHSUM_ERROR:
			return error_hashsum_data;
		default:
			return error_sign_auth_data;	
	}
	return error_sign_auth_data;
}

Json::Value DFVAClient::parse_json_data(string data, int default_error, bool check_connected=false){
	Json::Value root;   // will contains the root value after parsing.
	Json::Reader reader;
	bool parsingSuccessful = reader.parse( data, root );

	if ( !parsingSuccessful )
	{
		// report to the user the failure and their locations in the document.
		std::cerr  << "Failed to parse configuration\n"
				   << reader.getFormattedErrorMessages();
		return get_default_error(default_error);
	}

	try{
		if(check_connected){
			return root;
		}
		
		Json::FastWriter fastWriter;
		string datahash = fastWriter.write(root["data_hash"]);
		datahash.erase(datahash.begin()); // "
		datahash.erase(datahash.end()-1); // "
		datahash.erase(datahash.end()-1); // \n
		
		string dec_data = this->crypto.decrypt(root["data"].toStyledString());
		string newhash = this->crypto.get_hash_sum(dec_data, settings.ALGORITHM);
		
		if(newhash.compare(datahash) != 0){
				return this->get_default_error(HASHSUM_ERROR);
		}
		
		parsingSuccessful = reader.parse( dec_data, root );
		if ( !parsingSuccessful )
		{
			// report to the user the failure and their locations in the document.
			std::cerr  << "Failed to parse configuration\n"
					   << reader.getFormattedErrorMessages();
			return get_default_error(default_error);
		}
	}catch(...) {
		return get_default_error(default_error);
	}

	return root;
}

string DFVAClient::get_timezone(){
	std::time_t t = std::time(nullptr);
	char buf[40];
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", gmtime(&t));
	return string(buf);
}

Json::Value DFVAClient::authenticate(string identification){
	Json::Value data;
	data["institution"] =  settings.CODE;
	data["notification_url"]= settings.URL_NOTIFY;
	data["identification"]=identification;
	data["request_datetime"]= this->get_timezone();
	Json::Value params = this->get_post_params(data.toStyledString()); 
	string url = settings.DFVA_SERVER_URL + settings.AUTHENTICATE_INSTITUTION;

	string result = this->post((char *)url.c_str(), 
						(char *)params.toStyledString().c_str());


	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_ERROR);  
	return rdata;
}
Json::Value DFVAClient::autenticate_check(string code){
	Json::Value data;
	data["institution"] =  settings.CODE;
	data["notification_url"]= settings.URL_NOTIFY;
	data["request_datetime"]= this->get_timezone();
	Json::Value params = this->get_post_params(data.toStyledString());
	string url = settings.DFVA_SERVER_URL + settings.CHECK_AUTHENTICATE_INSTITUTION; 
	string replacement = "%s";
	url.replace(url.find(replacement), replacement.length(), code);

	string result = this->post((char *)url.c_str(), 
						(char *)params.toStyledString().c_str());


	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_ERROR); 	  

	return rdata;
}
bool DFVAClient::autenticate_delete(string code){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["request_datetime"]= this->get_timezone();
      Json::Value params = this->get_post_params(data.toStyledString()); 
      string url = settings.DFVA_SERVER_URL + settings.AUTHENTICATE_DELETE; 
      string replacement = "%s";
	  url.replace(url.find(replacement), replacement.length(), code);

	  string result = this->post((char *)url.c_str(), 
							(char *)params.toStyledString().c_str());
	  
	  Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_DELETE); 
	  bool dev=false;
	  if(rdata.isMember("result")){
		 dev=rdata["result"].asBool();
	  }
	  
	return dev;	
}
Json::Value DFVAClient::sign(string identification, string document, string resume, string format){
	if(!check_if_exists(SignFormatStr, SIGNFORMATSTR , format))
	 throw "Format is not supported";

	Json::Value data;
	data["institution"]=  settings.CODE;
	data["notification_url"]=settings.URL_NOTIFY;
	data["document"]= document;
	data["format"]= format;
	data["algorithm_hash"]= settings.ALGORITHM;
	data["document_hash"]= this->crypto.get_hash_sum(document, settings.ALGORITHM);
	data["identification"]=identification;
	data["resumen"]= resume;
	data["request_datetime"]= this->get_timezone();

	Json::Value params = this->get_post_params(data.toStyledString()); 
	string url = settings.DFVA_SERVER_URL + settings.SIGN_INSTUTION;

	string result = this->post((char *)url.c_str(), 
				(char *)params.toStyledString().c_str());


	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_ERROR);  
	return rdata;

}
Json::Value DFVAClient::sign_check(string code){
	Json::Value data;
	data["institution"] =  settings.CODE;
	data["notification_url"]= settings.URL_NOTIFY;
	data["request_datetime"]= this->get_timezone();
	Json::Value params = this->get_post_params(data.toStyledString()); 
	string url = settings.DFVA_SERVER_URL + settings.CHECK_SIGN_INSTITUTION; 
	string replacement = "%s";
	url.replace(url.find(replacement), replacement.length(), code);

	string result = this->post((char *)url.c_str(), 
						(char *)params.toStyledString().c_str());


	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_ERROR); 	  

	return rdata;
}
bool DFVAClient::sign_delete(string code){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["request_datetime"]= this->get_timezone();
      Json::Value params = this->get_post_params(data.toStyledString()); 
      string url = settings.DFVA_SERVER_URL + settings.SIGN_DELETE; 
      string replacement = "%s";
	  url.replace(url.find(replacement), replacement.length(), code);

	  string result = this->post((char *)url.c_str(), 
							(char *)params.toStyledString().c_str());
	  
	  Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_DELETE); 
	  bool dev=false;
	  if(rdata.isMember("result")){
		 dev=rdata["result"].asBool();
	  }
	  
	return dev;			
}
Json::Value DFVAClient::validate(string document, string format){
	Json::Value data;
	string url;
	if(!check_if_exists(ValidateFormatStr, VALIDATEFORMATSTR,format))
	 throw "Format is not supported";
	
	data["institution"] =  settings.CODE;
	data["notification_url"]= settings.URL_NOTIFY;
	data["document"]=document;
	data["request_datetime"]= this->get_timezone();
	
	if(format.compare("certificate")==0){
		url = settings.DFVA_SERVER_URL + settings.VALIDATE_CERTIFICATE;
	}else{
		data["format"] = format;
		url = settings.DFVA_SERVER_URL + settings.VALIDATE_DOCUMENT;
	}
	
	Json::Value params = this->get_post_params(data.toStyledString()); 
	string result = this->post((char *)url.c_str(), 
					(char *)params.toStyledString().c_str());


	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_ERROR);  
	return rdata;
}
bool DFVAClient::is_suscriptor_connected(string identification){
	Json::Value data;
	data["institution"] =  settings.CODE;
	data["notification_url"]= settings.URL_NOTIFY;
	data["identification"]=identification;
	data["request_datetime"]= this->get_timezone();
	Json::Value params = this->get_post_params(data.toStyledString()); 
	string url =  settings.DFVA_SERVER_URL +  settings.SUSCRIPTOR_CONNECTED;
	string result = this->post((char *)url.c_str(), 
						(char *)params.toStyledString().c_str());

	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_DELETE, true); 
	bool dev=false;
	if(rdata.isMember("is_connected")){
	   dev=rdata["is_connected"].asBool();
	}
	return dev;	
}

Json::Value DFVAClient::get_notify_data(string data){
	return this->parse_json_data(data, SIGN_AUTH_ERROR); 
}

size_t WriteCallback(char *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

string DFVAClient::_post(char * url, char * data){
	CURL *curl;
	CURLcode res;
	string readBuffer;
  
	/* In windows, this will init the winsock stuff */ 
	curl_global_init(CURL_GLOBAL_ALL);
 
  /* get a curl handle */ 
  curl = curl_easy_init();
  if(curl) {
	  
	  // Configure headers 
	  
    struct curl_slist *headers = NULL;
    headers= curl_slist_append(headers, "Accept: application/json");
    headers= curl_slist_append(headers, "Content-Type: application/json");
    headers= curl_slist_append(headers, "charsets: utf-8");
	  
	  
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */ 
       
       
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.38.0");
    /* Now specify the POST data */ 
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    /* Get response data */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
     
    
    if(!settings.DFVA_SERVER_PORT.empty()){
		std::string::size_type sz;
		curl_easy_setopt(curl, CURLOPT_PORT, 
			stol(settings.DFVA_SERVER_PORT, &sz)
		);
	}
  
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK){
		cerr <<  "curl_easy_perform() failed: %s\n" << 
              curl_easy_strerror(res) << endl;
      curl_easy_cleanup(curl);
      throw "Curl response is not OK";
	}
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }else{
	 throw "Curl could not be inicializated";
  }
  curl_global_cleanup();
  return readBuffer;
}

string DFVAClient::post(char * url, char * data){
	string dev;
	try{
		dev = _post(url, data);
	}catch(const exception &e) {
		cerr << "Standard exception: " << e.what() << endl;
		dev="";
	}catch(...) {
		dev="";
	}
	return dev;
}

