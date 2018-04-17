#include <iostream>
#include "client.h"
#include <jsoncpp/json/json.h>
#include <curl/curl.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#define SIGN_AUTH_ERROR 1
#define VALIDATE_ERROR 2
#define SIGN_AUTH_DELETE 3

using namespace std;
using namespace Json;

const char* SignFormatStr[] = {
      "xml_cofirma",
      "xml_contrafirma",
      "odf",
      "msoffice"
};

const char* ValidateFormatStr[]{
	"certificate", 
	"cofirma", 
	"contrafirma", 
	"odf", 
	"msoffice"
};

const char* AlgorithmStr[] = {
      "sha256",
	  "sha384",
	  "sha512"
};

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
    
    error_delete["result"] = false;
		
}
void DFVAClient::set_algorithm(string new_algorithm){
	algorithm=new_algorithm;
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

Json::Value DFVAClient::parse_json_data(string data, int defualt_error){
	Json::Value root;   // will contains the root value after parsing.
	Json::Reader reader;
	bool parsingSuccessful = reader.parse( data, root );

	if ( !parsingSuccessful )
	{
		// report to the user the failure and their locations in the document.
		std::cout  << "Failed to parse configuration\n"
				   << reader.getFormattedErrorMessages();
		switch(defualt_error){
			case SIGN_AUTH_ERROR:
				return error_sign_auth_data;
			case VALIDATE_ERROR:
				return error_validate_data;
			case SIGN_AUTH_DELETE:
				return error_delete;
			
			default:
				return error_sign_auth_data;
			
		}
	}

	
	string dec_data = this->crypto.decrypt(root["data"].toStyledString());
	parsingSuccessful = reader.parse( dec_data, root );

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
Json::Value DFVAClient::validate(string document, string type, string format){
	Json::Value data;
	data["institution"] =  settings.CODE;
	data["notification_url"]= settings.URL_NOTIFY;
	data["document"]=document;
	data["request_datetime"]= this->get_timezone();
	Json::Value params = this->get_post_params(data.toStyledString()); 
	string url = settings.DFVA_SERVER_URL + settings.AUTHENTICATE_INSTITUTION;

	string result = this->post((char *)url.c_str(), 
					(char *)params.toStyledString().c_str());


	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_ERROR);  
	return rdata;
}
bool DFVAClient::is_suscriptor_connected(string identification, string format){
	Json::Value data;
	data["institution"] =  settings.CODE;
	data["notification_url"]= settings.URL_NOTIFY;
	data["identification"]=identification;
	data["request_datetime"]= this->get_timezone();
	Json::Value params = this->get_post_params(data.toStyledString()); 
	string url = settings.SUSCRIPTOR_CONNECTED;
	string result = this->post((char *)url.c_str(), 
						(char *)params.toStyledString().c_str());

	Json::Value rdata = this->parse_json_data(result, SIGN_AUTH_DELETE); 
	bool dev=false;
	if(rdata.isMember("result")){
	   dev=rdata["result"].asBool();
	}
	return dev;	
}

size_t WriteCallback(char *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

string DFVAClient::post(char * url, char * data){
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
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
 
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return readBuffer;
}
