#include "SkgServer.h"


string SkgServer::public_file_name = "public.skg";
string SkgServer::secrets_file_name = "secrets.skg";
string SkgServer::report_file_name = "report.skg";

SkgServer::SkgServer(SkgEnclave* pEnclave) : m_pEnclave(pEnclave), m_pClient(NULL) { }

SkgServer::~SkgServer(){
    delete m_pClient;
    SafeFree(this->p_skg_pk);
    SafeFree(this->p_sealed_s_sk);
}

bool SkgServer::writeAssets()
{
    if(!writeEncodedAssets(Settings::assets_path + SkgServer::secrets_file_name, 
                   (uint8_t*)this->p_sealed_s_sk, 
                   SKG_DATA_SEALED_SIZE_BYTES, 
                   SKG_DATA_SEALED_BASE64_SIZE_BYTES))
    {
        Log("SkgServer::writeAssets writeAssets failed");
        return false;
    }

    sgx_sealed_data_t* sealed = (sgx_sealed_data_t*)malloc(SKG_DATA_SEALED_SIZE_BYTES);

    if(!readEncodedAssets(Settings::assets_path + SkgServer::secrets_file_name, 
                  (uint8_t*)sealed, 
                  SKG_DATA_SEALED_SIZE_BYTES, 
                  SKG_DATA_SEALED_BASE64_SIZE_BYTES)) 
    {
    
        Log("SkgServer::readAssets sealed_s_sk failed");
        return false;
    }

    assert(0==memcmp(p_sealed_s_sk, sealed, SKG_DATA_SEALED_SIZE_BYTES));

    if(!writeEncodedAssets(Settings::assets_path + SkgServer::public_file_name, 
                   (uint8_t*)this->p_skg_pk, 
                   sizeof(sgx_ec256_public_t), 
                   PK_BASE64_SIZE_BYTES))
    {
        Log("SkgServer::writeAssets writeAssets failed");
        return false;
    }

    sgx_ec256_public_t pk;

    if(!readEncodedAssets(Settings::assets_path + SkgServer::public_file_name, 
                  (uint8_t*)&pk, 
                  sizeof(sgx_ec256_public_t), 
                  PK_BASE64_SIZE_BYTES)) 
    {
    
        Log("SkgServer::readAssets sealed_s_sk failed");
        return false;
    }

    assert(0==memcmp(&pk, this->p_skg_pk, sizeof(sgx_ec256_public_t)));

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

    if(!readEncodedAssets(Settings::assets_path + SkgServer::secrets_file_name, 
                  (uint8_t*)this->p_sealed_s_sk, 
                  SKG_DATA_SEALED_SIZE_BYTES, 
                  SKG_DATA_SEALED_BASE64_SIZE_BYTES)) 
    {
    
        Log("SkgServer::readAssets sealed_s_sk failed");
        return false;
    }

    if(!readEncodedAssets(Settings::assets_path + SkgServer::public_file_name, 
                  (uint8_t*)this->p_skg_pk, 
                  sizeof(sgx_ec256_public_t), 
                  PK_BASE64_SIZE_BYTES)) 
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

bool SkgServer::Init() {

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

    Log("SkgServer::Init succeeded");
    return true;
}

bool SkgServer::processPkRequest(Messages::PkRequest& pkRequest, 
                                 Messages::CertificateMSG& certMsg){
    

    //TODO: process pk request

    sgx_ec256_public_t ga = m_pClient->getGa();
    
    certMsg.set_type(THC_PK_RES);

    if(!m_report.toCertMsg(&ga, p_skg_pk, certMsg)){
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