#include "BbClient.h"


BbClient::BbClient(Enclave* pEnclave) : m_pEnclave(pEnclave), m_pClient(NULL) {
    
    m_pClient = new AttestationClient(m_pEnclave, m_report);
}

BbClient::~BbClient(){
    delete m_pClient;
    SAFE_FREE(this->p_sealed_s); 
}

bool BbClient::Init() {

    if(readSecret())
    {
        Log("BbClient already has secret, no need for attestation");
        return true;
    }

    if(!obtainCertificate())
    {
        Log("BbClient Failed to obtain a valid certificate");
        return false;
    }       

    Log("BbClient::Init succeeded");
    return true; 
}

bool BbClient::writeSecret()
{
    int fd = open((Settings::sealed_secret + ".bb").c_str(), O_WRONLY | O_CREAT, 0644);
    if(fd == -1){
       Log("BbClient::writeSecret can't open file, error is %s", strerror(errno));
       return false; 
    }

    std::string base64encoded_sealed_secret = 
        base64_encode(reinterpret_cast<unsigned char const*>(this->p_sealed_s), 
                      SECRET_KEY_SEALED_SIZE_BYTES);

    assert(base64encoded_sealed_secret.length() == SECRET_KEY_SEALED_BASE64_SIZE_BYTES);
     
    ssize_t ret_out = write(fd, base64encoded_sealed_secret.c_str(), 
                            SECRET_KEY_SEALED_BASE64_SIZE_BYTES);
    
    if(ret_out != SECRET_KEY_SEALED_BASE64_SIZE_BYTES){        
        Log("BbClient::writeSecret failed to write");
        return false;
    }

    Log("BbClient::writeSecret success");
    return true;
}

bool BbClient::readSecret() {

    SAFE_FREE(this->p_sealed_s);

    int fd = open((Settings::sealed_secret + ".bb").c_str(), O_RDONLY);
    if(fd == -1){
       Log("BbClient::readSecret no sealed secret file found");
       return false; 
    }

    char sealed_secret_encoded_buf[SECRET_KEY_SEALED_BASE64_SIZE_BYTES];
    size_t read_size = read(fd, sealed_secret_encoded_buf, 
                            SECRET_KEY_SEALED_BASE64_SIZE_BYTES);

    if(read_size != SECRET_KEY_SEALED_BASE64_SIZE_BYTES)
    {
       Log("BbClient::readSecret read %d bytes instead of %d", read_size, 
       SECRET_KEY_SEALED_BASE64_SIZE_BYTES);

       return false;
    }

    std::string base64encoded_sealed_secret(sealed_secret_encoded_buf);

    char const *c = base64_decode(base64encoded_sealed_secret).c_str();

    this->p_sealed_s = (sgx_sealed_data_t*)malloc(SECRET_KEY_SEALED_SIZE_BYTES);
    memcpy(this->p_sealed_s, c, SECRET_KEY_SEALED_SIZE_BYTES);

    Log("BbClient::readSecret succeeded");
    return true;
}

bool BbClient::obtainCertificate(){
    if(m_report.isValid())
    {
         Log("BbClient::obtainCertificate - already has a valid certificate");
         return true;
    }
    m_pClient->init();
    m_pClient->start();
    return m_report.isValid();
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

    getSecretRequest.set_type(THC_SEC_REQ);

    for (auto x : this->p_bb_pk->gx)
        getSecretRequest.add_gx(x);

    for (auto x : this->p_bb_pk->gy)
        getSecretRequest.add_gy(x);

    //TODO: add attestation report

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