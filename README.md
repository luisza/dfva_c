# dfva cliente para C/C++

Este cliente permite comunicarse con [DFVA](https://github.com/luisza/dfva) para proveer servicios de firma digital para Costa Rica a institutiones.

Utiliza c++11 para manejar y tiene las siguientes dependencias

* libicu para soporte de hora y zona horaria.
* libcurl4-openssl  cliente para la gestion de peticiones al servidor.
* libjsoncpp  Manejo de formato JSON usado en la comunicación con el servidor.
* libconfig8  Manejo del archivo de configuración.
* libcrypto++ Utilizado para la encripción y desencripción de mensajes.

Para instalarse en entornos derivados de Debian puede usarse 

```
apt-get install libconfig8-dev libcurl4-openssl-dev libjsoncpp-dev libicu-dev libcrypto++-dev
```

Para compilar el fuente y probar su funcionalidad puede modificar el archivo main.cpp y ejecutar

```
make dfva
```

# Modo de uso 

Este cliente permite:

* Autenticar personas y verificar estado de autenticación
* Firmar documento xml, odf, ms office, pdf y verificar estado de firma durante el tiempo que el usuario está firmando
* Validar un certificado emitido con la CA nacional de Costa Rica provista por el BCCR
* Validar un documento XML firmado.
* Revisar si un suscriptor está conectado.

##  Ejemplo de uso

Para la construcción del archivo de configuraciones (se crea automáticamente si no existe cuando se usa el cliente).
```
#include <dfva_c/settingsmanager.h>
AppSettings appsettings;
settings.save(appsettings);
```
Este paso no es requerido para el uso del cliente, pero puede ser útil para ver las opciones de configuración del cliente.

### Autenticación y su respectiva verificación

```
#include <stdio.h>
#include <dfva_c/client.h>
#include <jsoncpp/json/json.h>
using namespace std;

DFVAClient client;
Json::Value value = client.authenticate("402120119");
cout <<"Auth: "<< value.toStyledString() << endl;
value = client.autenticate_check(value["id_transaction"].asString());
cout <<"check auth: "<< value.toStyledString() << endl;
cout <<"del auth: "<< client.autenticate_delete(value["id_transaction"].asString()) << endl;
```
Este cliente parte del principio de proporcionar la menor cantidad de excepciones posibles, por ello se pretende siempre obtener un objeto Json con un formato predefinido, una clave de mucho valor es "status", la cual en caso de error inexperado tendrá un valor de 2 y en "status_text" una descripción del error.

### Firma de documentos y su respectiva verificación

El documento debe estar en base64 en string, para ello puede usar la utilidad en cripto.h "base64encode(const unsigned char \*input, int length)".

Las líneas de include se omiten para mejor lectura, pues son las mismas de autenticación en el resto de este Readme.

```
string document ="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBC..." 
value = client.sign("0804440119", document, "un resumen del documento para humanos", "pdf");
cout <<"Sign: "<< value.toStyledString() << endl;
value = client.sign_check(value["id_transaction"].asString());
cout <<"check Sign: "<< value.toStyledString() << endl; 
cout <<"del sign: "<< client.sign_delete(value["id_transaction"].asString()) << endl;
```

El último parámetro puede tener los siguientes valores:

- xml_cofirma
- xml_contrafirma
- odf
- msoffice
- pdf

### Verificación de certificados y documentos

```
string document ="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBC..." 
value = client.validate(document, "pdf");
cout <<"validate doc: "<< value.toStyledString() << endl;
```

El último parámetro puede tener los siguientes valores:

- certificate 
- cofirma 
- contrafirma 
- odf 
- msoffice
- pdf

Cuando se usa "certificate" se verificará como un certificado de la raíz nacional y el resultado varía considerablemente del objeto Json de documento.

### Verificación de un usuario conectado 

El resultado es siempre true o false, en caso de algún problema de conexión con el servidor retornará false.

```
cout << client.is_suscriptor_connected("03018801234") << endl;
```
