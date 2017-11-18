#include "SkgServer.h"


SkgServer::SkgServer(Enclave* pEnclave) : m_pEnclave(pEnclave), m_pClient(NULL) {
    
    m_pClient = new AttestationClient(m_pEnclave, m_report);
}

SkgServer::~SkgServer(){
    delete m_pClient;
}

bool SkgServer::obtainCertificate(){
    if(m_report.isValid())
    {
         Log("SkgServer::obtainCertificate - already has a valid certificate");
         return true;
    }
    if(readCertificateFromMemory())
    {
        Log("SkgServer::obtainCertificate - certificate read from memory successfully");
        return true;
    }
    m_pClient->init();
    m_pClient->start();
    return m_report.isValid();
}

bool SkgServer::readCertificateFromMemory(){
    Log("SkgServer::readCertificateFromMemory - not implemented");
    return false;
}


bool SkgServer::Init() {

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

    if(!obtainCertificate())
    {
        Log("SkgServer Failed to obtain a valid certificate");
        return false;
    }       

    Log("SkgServer::Init succeeded");
    return true;
}

bool SkgServer::processPkRequest(Messages::PkRequest& pkRequest, 
                                 Messages::PkResponse& pkResponse){
    //TODO: process pk request
    
    pkResponse.set_type(THC_PK_RES);

    for (auto x : p_skg_pk->gx)
        pkResponse.add_gx(x);

    for (auto x : p_skg_pk->gy)
        pkResponse.add_gy(x);
    
    //TODO: add attestation report

    Log("SkgServer::processPkRequest - success");
    return true;
} 


bool SkgServer::processGetSecretRequest(Messages::GetSecretRequest& getSecretRequest, 
                                        Messages::GetSecretResponse& getSecretResponse){

    //TODO: Extract attestation report (from getSecretRequest) and Verify

    sgx_status_t status;
    sgx_ec256_public_t bb_pk;

    for (int i=0; i< SGX_ECP256_KEY_SIZE; i++) {
        bb_pk.gx[i] = getSecretRequest.gx(i);
        bb_pk.gy[i] = getSecretRequest.gy(i);
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