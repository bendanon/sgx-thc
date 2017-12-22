#include "BbClient.h"


string BbClient::secret_file_name = "secret.bb";

BbClient::BbClient(BbEnclave* pEnclave, int port) : m_pEnclave(pEnclave), m_pClient(NULL) { 
    m_nmc = NetworkManagerClient::getInstance(Settings::rh_port, Settings::rh_host);
    m_nms = NetworkManagerServer::getInstance(port);

}

BbClient::~BbClient(){
    delete m_pClient;
    SafeFree(this->p_sealed_s); 
}

void BbClient::obtainSecretFromSkg() {
    m_nmc->Init();
    m_nmc->connectCallbackHandler([this](string v, int type) {
        return this->incomingHandler(v, type);
    });
    m_nmc->startService();
}

void BbClient::acceptInputFromNeighbors(){

    m_nms->Init();
    m_nms->connectCallbackHandler([this](string v, int type) {
        return this->incomingHandler(v, type);
    });
    m_nms->startService();

}

bool BbClient::hasSecret() {

    if(!readSecret()) {
        Log("BbClient::hasSecret - no secret, need for attestation");
        return false;
    }

    Log("BbClient::hasSecret succeeded");
    return true; 
}

bool BbClient::writeSecret()
{
    if(!writeToFile(Settings::assets_path + BbClient::secret_file_name, 
                   (uint8_t*)this->p_sealed_s, 
                   SECRET_KEY_SEALED_SIZE_BYTES))
    {
        Log("BbClient::writeSecret writeToFile failed");
        return false;
    }

    Log("BbClient::writeSecret success");
    return true;
}

bool BbClient::readSecret() {

    SafeFree(this->p_sealed_s);
    this->p_sealed_s = (sgx_sealed_data_t*)malloc(SECRET_KEY_SEALED_SIZE_BYTES);

    if(!readFromFile(Settings::assets_path + BbClient::secret_file_name, 
                  (uint8_t*)this->p_sealed_s, 
                  SECRET_KEY_SEALED_SIZE_BYTES)) 
    {
    
        Log("BbClient::readSecret readFromFile failed");
        return false;
    }    

    Log("BbClient::readSecret succeeded");
    return true;
}

bool BbClient::obtainCertificate(){
    if(m_report.isValid())
    {
         Log("BbClient::obtainCertificate - already has a valid certificate");
         return true;
    }
    
    if(this->p_bb_pk == NULL){
        Log("BbClient::obtainCertificate - called before bbInit1");
        return false;
    }

    m_pClient = new AttestationClient(m_pEnclave, m_report, this->p_bb_pk);
    m_pClient->init();
    m_pClient->start();
    return m_report.isValid();
}

bool BbClient::generatePkRequest(Messages::PkRequest& pkRequest){
    pkRequest.set_type(THC_PK_REQ);
    Log("BbClient::generatePkRequest - success");
    return true;
}


bool BbClient::processPkResponse(Messages::CertificateMSG& skgCertMsg, 
                                 Messages::CertificateMSG& bbCertMsg) {                    

    //Extract attestation report, verify its signature and verify skg pk with it
    VerificationReport skgReport;
    if(!skgReport.fromCertMsg(skgCertMsg)){
        Log("BbClient::processPkResponse - failed to verify skg verification report");
        return false;
    }
    
    /*Here we know skg_pk is authentic :)*/

    //Extract skg pk
    sgx_ec256_public_t skg_pk;

    for (int i=0; i< SGX_ECP256_KEY_SIZE; i++) {
        skg_pk.gx[i] = skgCertMsg.gx(i);
        skg_pk.gy[i] = skgCertMsg.gy(i);
    }

    //Sealed data structs
    this->p_sealed_k = (sgx_sealed_data_t*)malloc(SECRET_KEY_SEALED_SIZE_BYTES);
    memset(this->p_sealed_k, 0, SECRET_KEY_SEALED_SIZE_BYTES);
    this->p_sealed_k->key_request.key_policy = KEYPOLICY_MRENCLAVE;    

    //pk structs
    this->p_bb_pk = (sgx_ec256_public_t*)malloc(sizeof(sgx_ec256_public_t));    
    size_t pk_size = sizeof(sgx_ec256_public_t);
    memset(this->p_bb_pk, 0, pk_size);
    
    sgx_status_t status;
    status = m_pEnclave->bbInit1(this->p_sealed_k, SECRET_KEY_SEALED_SIZE_BYTES, 
                                 this->p_bb_pk, &skg_pk, pk_size);

    if(status) {
        Log("bb_init_1 failed with status %d", status);
        return false;
    }

    if(!obtainCertificate()){
        Log("BbClient Failed to obtain a valid certificate");
        return false;
    }       


    /*prepare getSecretRequest*/
    bbCertMsg.set_type(THC_SEC_REQ);

    if(!m_report.toCertMsg(this->p_bb_pk, bbCertMsg)){
        Log("BbClient::processPkResponse - toCertMsg falied");
        return false;    
    }

    Log("BbClient::processPkResponse succeeded");
    return true;
} 


bool BbClient::processGetSecretResponse(Messages::GetSecretResponse& getSecretResponse){

    sgx_status_t status;
    sgx_status_t retval;

    uint8_t s_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES];
    memset(s_encrypted, 0, SECRET_KEY_ENCRYPTED_SIZE_BYTES);

    for (int i=0; i< SECRET_KEY_ENCRYPTED_SIZE_BYTES; i++) {
        s_encrypted[i] = getSecretResponse.encrypted_secret(i);
    }

    //Sealed data structs
    this->p_sealed_s = (sgx_sealed_data_t*)malloc(SECRET_KEY_SEALED_SIZE_BYTES);
    memset(this->p_sealed_s, 0, SECRET_KEY_SEALED_SIZE_BYTES);
    this->p_sealed_s->key_request.key_policy = KEYPOLICY_MRENCLAVE;

    status = m_pEnclave->bbInit2(this->p_sealed_k, 
                                 s_encrypted, SECRET_KEY_ENCRYPTED_SIZE_BYTES,
                                 this->p_sealed_s, SECRET_KEY_SEALED_SIZE_BYTES);
                       
    if(status)
    {
        Log("bbInit2 status is %d", status);
        return false;
    }

    if(!writeSecret())
    {
        Log("BbClient::processGetSecretResponse failed to write secret");
        return false;
    }

    Log("BbClient::processGetSecretResponse - success");
    return true;
}

bool BbClient::execute(uint8_t* B_in, size_t B_in_size, 
                       uint8_t* B_out, size_t B_out_size) {


    sgx_status_t status;    

    status = m_pEnclave->bbExec(this->p_sealed_s, SECRET_KEY_SEALED_SIZE_BYTES, 
                                B_in, B_in_size, 
                                B_out, B_out_size);

    if(status)
    {
        Log("bbExec failed with status is %d", status);
        return false;
    }

    Log("BbClient::execute - success");
    return true;
}

vector<string> BbClient::incomingHandler(string v, int type) {
    vector<string> res;
    bool ret;
    string s;

    if(type == THC_FAILED_READ)
    {
        Log("BbClient::incomingHandler - Failed read, restarting");
        //restart();
        return res;
    }

    if (!v.empty()) {

        switch (type) {
            case THC_PK_RES: {
                Messages::CertificateMSG pkResponse;
                Messages::CertificateMSG getSecretRequest;
                ret = pkResponse.ParseFromString(v);
                if (ret && (pkResponse.type() == THC_PK_RES)){
                    if(this->processPkResponse(pkResponse, getSecretRequest) && getSecretRequest.SerializeToString(&s)){                        
                        res.push_back(to_string(THC_SEC_REQ));                        
                    }
                    else {
                        Log("BbClient::incomingHandler - processPkRequest failed");
                    }                
                }
            }
            break;
            case THC_SEC_RES: {
                Messages::GetSecretResponse getSecretResponse;
                ret = getSecretResponse.ParseFromString(v);
                if (ret && (getSecretResponse.type() == THC_SEC_RES)){
                    if(this->processGetSecretResponse(getSecretResponse)){
                        Log("BbClient::incomingHandler - processGetSecretResponse succeeded");
                    }
                    else {
                        Log("BbClient::incomingHandler - processGetSecretResponse failed");
                    }                
                }
            }
            break;
            default:
                Log("Unknown type: %d", type, log::error);
                break;
        }

    } else {
        Messages::PkRequest pkRequest;
        if (this->generatePkRequest(pkRequest) && pkRequest.SerializeToString(&s)){
            res.push_back(to_string(THC_PK_REQ));
        } else { 
            Log("BbClient::incomingHandler - generatePkRequest failed");            
        }
    }

    res.push_back(s);
    return res;
}