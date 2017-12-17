#include "SkgServer.h"


string SkgServer::public_file_name = "public.skg";
string SkgServer::secrets_file_name = "secrets.skg";
string SkgServer::report_file_name = "report_";

SkgServer::SkgServer(SkgEnclave* pEnclave) : m_pEnclave(pEnclave), m_pClient(NULL) { }

SkgServer::~SkgServer(){
    delete m_pClient;
    SafeFree(this->p_skg_pk);
    SafeFree(this->p_sealed_s_sk);
}

bool SkgServer::writeAssets()
{
    if(!writeToFile(Settings::assets_path + SkgServer::secrets_file_name, 
                   (uint8_t*)this->p_sealed_s_sk, 
                   SKG_DATA_SEALED_SIZE_BYTES))
    {
        Log("SkgServer::writeAssets writeToFile failed");
        return false;
    }

    if(!writeToFile(Settings::assets_path + SkgServer::public_file_name,
                   (uint8_t*)this->p_skg_pk, 
                   sizeof(sgx_ec256_public_t)))
    {
        Log("SkgServer::writeAssets writeToFile failed");
        return false;
    }

    if(!m_report.write(Settings::assets_path + SkgServer::report_file_name)) {
        Log("SkgServer::writeAssets report failed");
        return false;
    }

    Log("SkgServer::writeAssets success");
    return true;
}

bool SkgServer::readAssets() {

    SafeFree(this->p_sealed_s_sk);
    this->p_sealed_s_sk = (sgx_sealed_data_t*)malloc(SKG_DATA_SEALED_SIZE_BYTES);

    SafeFree(this->p_skg_pk);
    this->p_skg_pk = (sgx_ec256_public_t*)malloc(sizeof(sgx_ec256_public_t));    

    if(!readFromFile(Settings::assets_path + SkgServer::secrets_file_name, 
                  (uint8_t*)this->p_sealed_s_sk, 
                  SKG_DATA_SEALED_SIZE_BYTES)) 
    {
    
        Log("SkgServer::readAssets sealed_s_sk failed");
        return false;
    }

    if(!readFromFile(Settings::assets_path + SkgServer::public_file_name, 
                  (uint8_t*)this->p_skg_pk, 
                  sizeof(sgx_ec256_public_t))) 
    {
    
        Log("SkgServer::readAssets p_skg_pk failed");
        return false;
    }

    if(!m_report.read(Settings::assets_path + SkgServer::report_file_name)){

        Log("SkgServer::readAssets report failed");
        return false;
    }

    Log("SkgServer::readAssets succeeded");
    return true;
}

bool SkgServer::obtainAssets(){

    sgx_status_t status;

    //Sealed data structs
    this->p_sealed_s_sk = (sgx_sealed_data_t*)malloc(SKG_DATA_SEALED_SIZE_BYTES);
    memset(this->p_sealed_s_sk, 0, SKG_DATA_SEALED_SIZE_BYTES);
    this->p_sealed_s_sk->key_request.key_policy = KEYPOLICY_MRENCLAVE;

    //pk structs
    this->p_skg_pk = (sgx_ec256_public_t*)malloc(sizeof(sgx_ec256_public_t));    
    size_t pk_size = sizeof(sgx_ec256_public_t);
    memset(this->p_skg_pk, 0, pk_size);

    status = m_pEnclave->skgInit(this->p_sealed_s_sk, 
                                SKG_DATA_SEALED_SIZE_BYTES, 
                                this->p_skg_pk, 
                                pk_size);

    
    if(status)
    {
        Log("SkgInit failed, status is %d", status);
        return false;
    }

    m_pClient = new AttestationClient(m_pEnclave, m_report, this->p_skg_pk);
    m_pClient->init();
    m_pClient->start(); 

    if(!m_report.isValid())
    {
        Log("SkgServer::Init invalid report"); 
        return false;
    }

    Log("SkgServer::obtainAssets succeeded");
    return true;
}

bool SkgServer::init() {

    if(readAssets())
    {
        Log("SkgServer::Init - assets read from memory successfully");
        return true;
    }

    if(!obtainAssets())
    {
        Log("SkgServer::Init - obtainAssets failed");
        return false;
    }    

    if(!writeAssets())
    {
        Log("SkgServer::Init failed to write assets"); 
        return false;
    }

    /*this->nm->Init();
    this->nm->connectCallbackHandler([this](string v, int type) {
        return this->incomingHandler(v, type);
    });*/

    Log("SkgServer::Init succeeded");
    return true;
}

void SkgServer::start() {
    this->nm->startService();
    Log("SkgServer done");
    //TODO - handle more than a single session 
}

bool SkgServer::processPkRequest(Messages::PkRequest& pkRequest, 
                                 Messages::CertificateMSG& certMsg){
    

    //TODO: process pk request    
    certMsg.set_type(THC_PK_RES);

    if(!m_report.toCertMsg(p_skg_pk, certMsg)){
        Log("SkgServer::processPkRequest - m_report.toCertMsg failed", log::error);
        return false;
    }

    Log("SkgServer::processPkRequest - success");
    return true;
} 


bool SkgServer::processGetSecretRequest(Messages::CertificateMSG& certMsg, 
                                        Messages::GetSecretResponse& getSecretResponse){


    //Extract attestation report, verify its signature and verify skg pk with it
    VerificationReport bbReport;
    if(!bbReport.fromCertMsg(certMsg)){
        Log("BbClient::processPkResponse - failed to verify bb verification report");
        return false;
    }

    /*Here we know bb_pk is authentic :)*/

    sgx_status_t status;
    sgx_ec256_public_t bb_pk;

    for (int i=0; i< SGX_ECP256_KEY_SIZE; i++) {
        bb_pk.gx[i] = certMsg.gx(i);
        bb_pk.gy[i] = certMsg.gy(i);
    }

    uint8_t s_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES];
    memset(s_encrypted, 0, SECRET_KEY_ENCRYPTED_SIZE_BYTES);


    status = m_pEnclave->skgExec(&bb_pk, p_skg_pk, sizeof(sgx_ec256_public_t),
                                 this->p_sealed_s_sk, SKG_DATA_SEALED_SIZE_BYTES,
                                 s_encrypted, SECRET_KEY_ENCRYPTED_SIZE_BYTES);
    
    if(status)
    {
        Log("skgExec failed, status is %d", status);
        return false;
    }

    getSecretResponse.set_type(THC_SEC_RES);

    for(auto x : s_encrypted)
        getSecretResponse.add_encrypted_secret(x);    

    Log("SkgServer::processGetSecretRequest - success");
    return false;
}

vector<string> SkgServer::incomingHandler(string v, int type) {
    vector<string> res;
    bool ret;
    string s;

    if(type == RA_FAILED_READ)
    {
        Log("SkgServer::incomingHandler - Failed read, restarting");
        //restart();
        return res;
    }

    switch (type) {
        case THC_PK_REQ: {            
            Messages::PkRequest pkRequest;
            Messages::CertificateMSG pkResponse;
            ret = pkRequest.ParseFromString(v);
            if (ret && (pkRequest.type() == THC_PK_REQ)){
                if(this->processPkRequest(pkRequest, pkResponse) && pkResponse.SerializeToString(&s)){
                    res.push_back(to_string(THC_PK_RES));
                    //res.push_back(nm->serialize(pkResponse));
                }
                else {
                    Log("SkgServer::incomingHandler - processPkRequest failed");
                }                
            }
        }
        break;
        case THC_SEC_REQ: {
            Messages::CertificateMSG getSecretRequest;
            Messages::GetSecretResponse getSecretResponse;
            ret = getSecretRequest.ParseFromString(v);
            if (ret && (getSecretRequest.type() == THC_SEC_REQ)){
                if(this->processGetSecretRequest(getSecretRequest, getSecretResponse) && getSecretResponse.SerializeToString(&s)){
                    res.push_back(to_string(THC_SEC_RES));
                    //res.push_back(nm->serialize(getSecretResponse));
                }
                else {
                    Log("SkgServer::incomingHandler - processGetSecretRequest failed");
                }                
            }
        }
        break;
        default:
            Log("Unknown type: %d", type, log::error);
            break;
    }

    res.push_back(s);

    return res;
}