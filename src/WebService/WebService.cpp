#include "WebService.h"
#include "../GeneralSettings.h"

WebService* WebService::instance = NULL;

WebService::WebService() : curl(NULL) {}

WebService::~WebService() {
    if (curl)
        curl_easy_cleanup(curl);
}


WebService* WebService::getInstance() {
    if (instance == NULL) {
        instance = new WebService();
    }

    return instance;
}


void WebService::init() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();

    if (curl) {
        Log("Curl initialized successfully");
		//curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );
        curl_easy_setopt( curl, CURLOPT_SSLCERTTYPE, "P12");
        curl_easy_setopt( curl, CURLOPT_SSLCERTPASSWD, "123");
        curl_easy_setopt( curl, CURLOPT_SSLCERT, Settings::ias_crt);
        curl_easy_setopt( curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        curl_easy_setopt( curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1L);
    } else
        Log("Curl init error", log::error);
}


vector<pair<string, string>> WebService::parseJSONfromIAS(string json) {

    if(curl == NULL){
        Log("WebService::parseJSONfromIAS - not initialized");
        return vector<pair<string, string>>();
    }

    Json::Value root;
    Json::Reader reader;
    bool parsingSuccessful = reader.parse(json.c_str(), root);

    if (!parsingSuccessful) {
        Log("Failed to parse JSON string from IAS", log::error);
        return vector<pair<string, string>>();
    }

    vector<pair<string,string>> values;

    string id = root.get("id", "UTF-8" ).asString();  
    values.push_back({"id", id});

    string isvEnclaveQuoteStatus = root.get("isvEnclaveQuoteStatus", "UTF-8" ).asString();
    values.push_back({"isvEnclaveQuoteStatus", isvEnclaveQuoteStatus});

    string isvEnclaveQuoteBody = root.get("isvEnclaveQuoteBody", "UTF-8" ).asString();
    values.push_back({"isvEnclaveQuoteBody", isvEnclaveQuoteBody});

    string platformInfoBlob = root.get("platformInfoBlob", "UTF-8" ).asString();
    values.push_back({"platformInfoBlob", platformInfoBlob});

    string revocationReason = root.get("revocationReason", "UTF-8" ).asString();
    values.push_back({"revocationReason", revocationReason});

    string pseManifestStatus = root.get("pseManifestStatus", "UTF-8" ).asString();
    values.push_back({"pseManifestStatus", pseManifestStatus});

    string pseManifestHash = root.get("pseManifestHash", "UTF-8" ).asString();
    values.push_back({"pseManifestHash", pseManifestHash});

    string nonce = root.get("nonce", "UTF-8" ).asString();
    values.push_back({"nonce", nonce});

    string timestamp = root.get("timestamp", "UTF-8" ).asString();
    values.push_back({"timestamp", timestamp});
   

     //TODO - What about X-IASReport-Signature and X-IASReport-Signing-Certificate? 
     //this should be extracted, verified and passed to AttestationClient as a part
     //of the report...

    return values;
}


string WebService::createJSONforIAS(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce) {
    Json::Value request;

    request["isvEnclaveQuote"] = Base64encodeUint8(quote, 1116);
//    request["pseManifest"] = Base64encodeUint8(quote, 256);		//only needed when enclave has been signed

    Json::FastWriter fastWriter;
    string output = fastWriter.write(request);

    return output;
}


size_t ias_response_header_parser(void *ptr, size_t size, size_t nmemb, void *userdata) {
    int parsed_fields = 0, response_status, content_length, ret = size * nmemb;

    char *x = (char*) calloc(size+1, nmemb);
    assert(x);
    memcpy(x, ptr, size * nmemb);
    parsed_fields = sscanf( x, "HTTP/1.1 %d", &response_status );

    if (parsed_fields == 1) {
        ((ias_response_header_t *) userdata)->response_status = response_status;
        return ret;
    }

    parsed_fields = sscanf( x, "content-length: %d", &content_length );
    if (parsed_fields == 1) {
        ((ias_response_header_t *) userdata)->content_length = content_length;
        return ret;
    }

    char *p_location = (char*) calloc(1, LOCATION_MAX_LEN);
    parsed_fields = sscanf(x, "location: %s", p_location );

    if (parsed_fields == 1) {
        std::string location_str( p_location );
        ( ( ias_response_header_t * ) userdata )->location = location_str;
        return ret;
    }

    char *p_iasreport_sig = (char*) calloc(1, X_IASREPORT_SIG_MAX_LEN);
    parsed_fields = sscanf(x, "x-iasreport-signature: %s", p_iasreport_sig );

    if (parsed_fields == 1) {
        std::string iasreport_sig_str( p_iasreport_sig );
        ( ( ias_response_header_t * ) userdata )->x_iasreport_signature = iasreport_sig_str;
        return ret;
    }

    char *p_iasreport_sig_cert = (char*) calloc(1, X_IASREPORT_SIG_CERT_MAX_LEN);
    parsed_fields = sscanf(x, "x-iasreport-signing-certificate: %s", p_iasreport_sig_cert );

    if (parsed_fields == 1) {
        std::string iasreport_sig_cert_str( p_iasreport_sig_cert );
        ( ( ias_response_header_t * ) userdata )->x_iasreport_signing_certificate 
            = iasreport_sig_cert_str;
        return ret;
    }

    char *p_request_id = (char*) calloc(1, REQUEST_ID_MAX_LEN);
    parsed_fields = sscanf(x, "request-id: %s", p_request_id );

    if (parsed_fields == 1) {
        std::string request_id_str( p_request_id );
        ( ( ias_response_header_t * ) userdata )->request_id = request_id_str;
        return ret;
    }    

    return ret;
}


size_t ias_reponse_body_handler( void *ptr, size_t size, size_t nmemb, void *userdata ) {
    size_t realsize = size * nmemb;
    ias_response_container_t *ias_response_container = ( ias_response_container_t * ) userdata;
    ias_response_container->p_response = (char *) realloc(ias_response_container->p_response, ias_response_container->size + realsize + 1);

    if (ias_response_container->p_response == NULL ) {
        Log("Unable to allocate extra memory", log::error);
        return 0;
    }

    memcpy( &( ias_response_container->p_response[ias_response_container->size]), ptr, realsize );
    ias_response_container->size += realsize;
    ias_response_container->p_response[ias_response_container->size] = 0;

    return realsize;
}


bool WebService::sendToIAS(string url,
                           IAS type,
                           string payload,
                           struct curl_slist *headers,
                           ias_response_container_t *ias_response_container,
                           ias_response_header_t *response_header) {

    if(curl == NULL){
        Log("WebService::parseJSONfromIAS - not initialized");
        return false;
    }
    CURLcode res = CURLE_OK;

    curl_easy_setopt( curl, CURLOPT_URL, url.c_str());

    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    }    

    ias_response_container->p_response = (char*) malloc(1);
    ias_response_container->size = 0;

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ias_response_header_parser);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response_header);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ias_reponse_body_handler);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ias_response_container);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        Log("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        return false;
    }

    return true;
}


bool WebService::getSigRL(string gid, string *sigrl) {
    Log("Retrieving SigRL from IAS");

    //check if the sigrl for the gid has already been retrieved once -> to save time
    for (auto x : retrieved_sigrl) {
        if (x.first == gid) {
            *sigrl = x.second;
            Log("sigrl for the gid has already been retrieved once");
            return true;
        }
    }

    ias_response_container_t ias_response_container;
    ias_response_header_t response_header;

    string url = Settings::ias_url + "sigrl/" + gid;

    bool ret = this->sendToIAS(url, IAS::sigrl, "", NULL, &ias_response_container, &response_header);

    if(!ret){
        Log("WebService::getSigRL - sendToIAS failed");
        return false;
    }


    Log("\tResponse status is: %d" , response_header.response_status);
    Log("\tContent-Length: %d", response_header.content_length);

    if (response_header.response_status == 200) {
        if (response_header.content_length > 0) {
            string response(ias_response_container.p_response);
            *sigrl = Base64decode(response);
        }
        retrieved_sigrl.push_back({gid, *sigrl});
        return true;
    } else
        return true;

    return false;
}


bool WebService::verifyQuote(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce, vector<pair<string, string>> *result) {
    string encoded_quote = this->createJSONforIAS(quote, pseManifest, nonce);

    ias_response_container_t ias_response_container;
    ias_response_header_t response_header;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    string payload = encoded_quote;

    string url = Settings::ias_url + "report";
    this->sendToIAS(url, IAS::report, payload, headers, &ias_response_container, &response_header);

    if (response_header.response_status == 200) {
        Log("Quote attestation successful, new report has been created");

        string response(ias_response_container.p_response);

        auto res = parseJSONfromIAS(response);
        res.push_back({"fullResponse", response});
        res.push_back({"x-iasreport-signature", response_header.x_iasreport_signature});
        res.push_back({"x-iasreport-signing-certificate", 
                        response_header.x_iasreport_signing_certificate});
        res.push_back({"location", response_header.location});
        *result = res;

    } else {
        Log("Quote attestation returned status: %d", response_header.response_status);
        return false;
    }

    return true;
}




