#include "BbClient.h"


BbClient::BbClient(Enclave* pEnclave) : m_pEnclave(pEnclave), m_pClient(NULL) {
    
    m_pClient = new AttestationClient(m_pEnclave, m_report);
}

BbClient::~BbClient(){
    delete m_pClient;
}

bool BbClient::Init() {
    if(!obtainCertificate())
    {
        Log("BbClient Failed to obtain a valid certificate");
        return false;
    }       

    Log("BbClient::Init succeeded");
    return true; 
}

bool BbClient::obtainCertificate(){
    if(m_report.isValid())
    {
         Log("BbClient::obtainCertificate - already has a valid certificate");
         return true;
    }
    if(readCertificateFromMemory())
    {
        Log("BbClient::obtainCertificate - certificate read from memory successfully");
        return true;
    }
    m_pClient->init();
    m_pClient->start();
    return m_report.isValid();
}

bool BbClient::readCertificateFromMemory(){
    Log("BbClient::readCertificateFromMemory - not implemented");
    return false;
}

bool BbClient::generatePkRequest(Messages::PkRequest& pkRequest){
    pkRequest.set_type(THC_PK_REQ);
    Log("BbClient::generatePkRequest - success");
    return true;
}


bool BbClient::processPkResponse(Messages::PkResponse& pkResponse, 
                                 Messages::GetSecretRequest& getSecretRequest){                    

    //TODO: Extract attestation report (from pkResponse) and Verify 
    
    sgx_ec256_public_t skg_pk;

    for (int i=0; i< SGX_ECP256_KEY_SIZE; i++) {
        skg_pk.gx[i] = pkResponse.gx(i);
        skg_pk.gy[i] = pkResponse.gy(i);
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

    if(status) 
    {
        Log("bb_init_1 failed with status %d", status);
        return false;
    }    

    Log("BbClient::processPkResponse succeeded");
    return true;
} 


bool BbClient::processGetSecretResponse(Messages::GetSecretResponse& getSecretResponse){
    Log("BbClient::processGetSecretResponse - not implemented");
    return false;
}