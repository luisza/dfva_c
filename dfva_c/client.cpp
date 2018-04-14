#include <iostream>
#include "client.h"
#include <jsoncpp/json/json.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

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
	
}
void DFVAClient::set_algorithm(string new_algorithm){
	algorithm=new_algorithm;
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
 
	return data;
}
Json::Value DFVAClient::check_autenticate(string code){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["request_datetime"]= this->get_timezone();
	return data;
}
bool DFVAClient::autenticate_delete(string code){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["request_datetime"]= this->get_timezone();
	return true;	
}
Json::Value DFVAClient::sign(string identification, string document, string resume, string format){
		Json::Value data;
		data["institution"]=  settings.CODE;
		data["notification_url"]=settings.URL_NOTIFY;
		data["document"]= document;
		data["format"]= format;
		data["algorithm_hash"]= settings.ALGORITHM;
	   // data["document_hash"]= get_hash_sum(document,  settings.ALGORITHM);
		data["identification"]=identification;
		data["resumen"]= resume;
		data["request_datetime"]= this->get_timezone();
		return data;

	}
Json::Value DFVAClient::check_sign(string code){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["request_datetime"]= this->get_timezone();
	return data;
}
bool DFVAClient::sign_delete(string code){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["request_datetime"]= this->get_timezone();
	return true;		
}
Json::Value DFVAClient::validate(string document, string type, string format){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["document"]=document;
      data["request_datetime"]= this->get_timezone();
	return data;
}
bool DFVAClient::is_suscriptor_connected(string identification, string format){
	  Json::Value data;
	  data["institution"] =  settings.CODE;
      data["notification_url"]= settings.URL_NOTIFY;
      data["identification"]=identification;
      data["request_datetime"]= this->get_timezone();
        
	return true;
}
