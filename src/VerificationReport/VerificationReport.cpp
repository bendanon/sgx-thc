#include "VerificationReport.h"
#include "sample_libcrypto.h"

VerificationReport::VerificationReport() : m_isValid(false), m_certificateValid(false) 
{ 
    memset(&m_quote_body, 0, sizeof(m_quote_body));
}
VerificationReport::~VerificationReport() { 
    X509_free(m_cert);
}


bool VerificationReport::setGa(sgx_ec256_public_t* p_ga){
     if(m_isValid){
        Log("VerificationReport::setGa - already valid");
        return false;
    }

    memcpy(&m_ga, p_ga, sizeof(sgx_ec256_public_t));

    return true;
}

bool VerificationReport::verifyPublicKey(sgx_ec256_public_t* p_gb){

    if(!m_isValid){
        Log("VerificationReport::verifyPublicKey - report is not valid");
        return false;
    }

    sgx_report_data_t report_data = {0};
    sgx_sha_state_handle_t sha_handle = NULL;

    // Verify the report_data in the Quote matches the expected value.
    // The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
    // The second 32 bytes of report_data are set to zero.
    sample_status_t sample_ret = sample_sha256_init(&sha_handle);
    if (sample_ret != SAMPLE_SUCCESS) {
        Log("Error, init hash failed", log::error);
        return false;
    }

    sample_ret = sample_sha256_update((uint8_t *)&m_ga, sizeof(sgx_ec256_public_t), sha_handle);
    if (sample_ret != SAMPLE_SUCCESS) {
        Log("Error, udpate hash failed", log::error);
        return false;
    }

    sample_ret = sample_sha256_update((uint8_t *)p_gb, sizeof(sgx_ec256_public_t), sha_handle);
    if (sample_ret != SAMPLE_SUCCESS) {
        Log("Error, udpate hash failed", log::error);
        return false;
    }

    Log("vk is %s", Base64encodeUint8((uint8_t*)Settings::const_vk, sizeof(Settings::const_vk)));

    sample_ret = sample_sha256_update(Settings::const_vk, sizeof(Settings::const_vk), sha_handle);
    if (sample_ret != SAMPLE_SUCCESS) {
        Log("Error, udpate hash failed", log::error);
        return false;
    }

    sample_ret = sample_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
    if (sample_ret != SAMPLE_SUCCESS) {
        Log("Error, Get hash failed", log::error);
        return false;
    }

    if (memcmp((uint8_t *)&report_data, (uint8_t *)&(m_quote_body.report_body.report_data), sizeof(report_data))) {
        Log("Error, verify hash failed", log::error);
        return false;
    }

    Log("VerificationReport::verifyPublicKey - success");
    return true;
}


bool VerificationReport::toCertMsg(sgx_ec256_public_t* p_gb, Messages::CertificateMSG& certMsg){ 

    if(!m_isValid) {
        Log("VerificationReport::toCertMsg - invalid", log::error);
        return false;
    }

    for (auto x : p_gb->gx)
        certMsg.add_gx(x);

    for (auto x : p_gb->gy)
        certMsg.add_gy(x);

    if(!insertIASCertificate(certMsg)){
        Log("VerificationReport::toCertMsg - m_report.insertIASCertificate failed", log::error);
        return false;
    }
    
    if(!insertIASSignature(certMsg)){
        Log("VerificationReport::toCertMsg - m_report.insertIASSignature failed", log::error);
        return false;
    }

    if(!insertIASFullResponse(certMsg)){
        Log("VerificationReport::toCertMsg- m_report.insertIASFullResponse failed", log::error);
        return false;
    }

    if(!insertGa(certMsg)){
        Log("VerificationReport::toCertMsg- m_report.insertGa failed", log::error);
        return false;
    }

    Log("VerificationReport::toCertMsg - success");
    return true;
}

bool VerificationReport::verifyMrEnclave(){
    Log("mrenclave is %s", Base64encodeUint8((uint8_t*)&m_quote_body.report_body.mr_enclave, sizeof(m_quote_body.report_body.mr_enclave)));
    return true; //TODO - compare to either skg mrenclave or bb mrenclave
}

bool VerificationReport::verifyMrSigner(){
    if(0!=memcmp(Settings::mrsigner, 
                 Base64encodeUint8((uint8_t*)&m_quote_body.report_body.mr_signer, sizeof(m_quote_body.report_body.mr_signer)).c_str(),
                 strlen(Settings::mrsigner)))
    {
        return false;
    }

    Log("VerificationReport::verifyMrSigner - success");
    return true;
}

std::string extractQuoteBody(const char* report_buf){
    char *tok = strstr(const_cast<char*>(report_buf), "isvEnclaveQuoteBody");
    int counter = 0;
    while ((tok = strtok(tok, "\"")) != NULL)
    {
        if(2 == counter) {
            std::string quoteBody(tok);
            return quoteBody;
        }        
        tok = NULL;
        counter++;
    }
    return "";
}

bool VerificationReport::fromCertMsg(Messages::CertificateMSG& certMsg, Enclave* pEnclave) {


    if(m_isValid) {
        Log("VerificationReport::fromCertMsg - already valid", log::error);
        return false;
    }

    if(NULL == pEnclave){
        Log("VerificationReport::fromCertMsg - pEnclave is NULL", log::error);
        return false;
    }

    /*Extract fields for certificate chain and signature verification*/

    if(!extractIASCertificate(certMsg)){
        Log("VerificationReport::fromCertMsg - extractIASCertificate failed", log::error);
        return false;
    }
    if(!extractIASSignature(certMsg)){
        Log("VerificationReport::fromCertMsg - extractIASSignature failed", log::error);
        return false;
    }
    if(!extractIASFullResponse(certMsg)){
        Log("VerificationReport::fromCertMsg - extractIASFullResponse failed", log::error);
        return false;
    }

    if(!extractGa(certMsg)){
        Log("VerificationReport::fromCertMsg - extractGa failed", log::error);
        return false;
    }

    /*Extract pk to verify it against quote body*/
    /*sgx_ec256_public_t pkToVerify;

    for (int i=0; i< SGX_ECP256_KEY_SIZE; i++) {
        pkToVerify.gx[i] = certMsg.gx(i);
        pkToVerify.gy[i] = certMsg.gy(i);
    }

    if(SGX_SUCCESS != pEnclave->VerifyPeer((unsigned char*) m_full_response.c_str(), m_full_response.length(), 
                                           (unsigned char*) m_x_iasreport_signing_certificate.c_str(), m_x_iasreport_signing_certificate.length(), 
                                           (unsigned char*) m_x_iasreport_signature.c_str(), m_x_iasreport_signature.length(),
                                           &pkToVerify, &m_ga, sizeof(m_ga)))
    {
        Log("VerificationReport::fromCertMsg - VerifyPeer failed", log::error);
        return false;
    }*/

    /*Verify the IAS response*/    
    if(!verifyCertificateChain()){
        Log("VerificationReport::fromResult - verifyCertificateChain failed");
        return false;
    }

    if(!verifySignature()) {
        Log("VerificationReport::fromResult - verifySignature failed");
        return false;
    }

    /*Extract isvEnclaveQuoteBody from the report*/
    string isvEnclaveQuoteBody = extractQuoteBody(m_full_response.c_str());
    memcpy(&m_quote_body, Base64decode(isvEnclaveQuoteBody).c_str(), sizeof(m_quote_body));

    if(!verifyMrSigner()){
        Log("VerificationReport::fromCertMsg - failed to mrsigner");
        return false;
    }

    if(!verifyMrEnclave()){
        Log("VerificationReport::fromCertMsg - failed to mrenclave");
        return false;
    }

    /*Extract pk to verify it against quote body*/
    sgx_ec256_public_t pkToVerify;

    for (int i=0; i< SGX_ECP256_KEY_SIZE; i++) {
        pkToVerify.gx[i] = certMsg.gx(i);
        pkToVerify.gy[i] = certMsg.gy(i);
    }

    if(!verifyPublicKey(&pkToVerify)){
        Log("VerificationReport::fromCertMsg - failed to verify pk");
        return false;
    }

    Log("VerificationReport::fromCertMsg - success");
    return true;
 }

 bool VerificationReport::read(std::string file){
    
 
    char* buf;
    if(0 == ReadFileToBuffer(file + "sig.skg", &buf)){
        Log("VerificationReport::read m_x_iasreport_signature failed");
        return false;
    }
    m_x_iasreport_signature = buf;
    free(buf);

    if(0 == ReadFileToBuffer(file + "cert.skg", &buf)){
        Log("VerificationReport::read m_x_iasreport_signing_certificate failed");
        return false;
    }
    m_x_iasreport_signing_certificate = buf;
    free(buf);

    if(0 == ReadFileToBuffer(file + "full.skg", &buf)){
        Log("VerificationReport::read m_full_response failed");
        return false;
    }
    m_full_response = buf;
    free(buf);


    if(!readFromFile(file + "quote.skg", (uint8_t*)&this->m_quote_body, sizeof(sgx_quote_t))) {    
        Log("VerificationReport::read quote failed");
        return false;
    }

    if(!readFromFile(file + "ga.skg", (uint8_t*)&this->m_ga, sizeof(sgx_ec256_public_t))) {    
        Log("VerificationReport::read ga failed");
        return false;
    }

    if(!verifyCertificateChain()){
        Log("VerificationReport::read - verifyCertificateChain failed");
        return false;
    }

    if(!verifySignature()) {
        Log("VerificationReport::read - verifySignature failed");
        return false;
    }

    Log("VerificationReport::read - success");
    return true;
 }

 bool VerificationReport::write(std::string file){

    SaveBufferToFile(file + "sig.skg", m_x_iasreport_signature);

    SaveBufferToFile(file + "cert.skg", m_x_iasreport_signing_certificate);

    SaveBufferToFile(file + "full.skg", m_full_response);

    if(!writeToFile(file + "quote.skg", (uint8_t*)&this->m_quote_body, sizeof(sgx_quote_t))) {
        Log("VerificationReport::write quote failed");
        return false;
    }

    if(!writeToFile(file + "ga.skg", (uint8_t*)&this->m_ga, sizeof(sgx_ec256_public_t))) {
        Log("VerificationReport::write ga failed");
        return false;
    }

    Log("VerificationReport::write - succeeded");
    return true;
 }

bool VerificationReport::isValid()
{
    return m_isValid;
}

bool VerificationReport::fromResult(vector<pair<string, string>> result)
{

    ias_quote_status_t quoteStatus; //TODO - remove

    string location, id,
           isvEnclaveQuoteBody,
           platformInfoBlob, 
           revocationReason,
           pseManifestStatus,
           pseManifestHash,
           nonce,
           /*epidPseudonym*/
           timestamp;

    for (auto x : result) {
        if (x.first == "id") {
            id = x.second;
        } else if (x.first == "isvEnclaveQuoteStatus") {

            if (x.second == "OK")
                quoteStatus = IAS_QUOTE_OK;
            else if (x.second == "SIGNATURE_INVALID")
                quoteStatus = IAS_QUOTE_SIGNATURE_INVALID;
            else if (x.second == "GROUP_REVOKED")
                quoteStatus = IAS_QUOTE_GROUP_REVOKED;
            else if (x.second == "SIGNATURE_REVOKED")
                quoteStatus = IAS_QUOTE_SIGNATURE_REVOKED;
            else if (x.second == "KEY_REVOKED")
                quoteStatus = IAS_QUOTE_KEY_REVOKED;
            else if (x.second == "SIGRL_VERSION_MISMATCH")
                quoteStatus = IAS_QUOTE_SIGRL_VERSION_MISMATCH;
            else if (x.second == "GROUP_OUT_OF_DATE")
                quoteStatus = IAS_QUOTE_GROUP_OUT_OF_DATE;

        } else if (x.first == "isvEnclaveQuoteBody") {
            memcpy(&m_quote_body, Base64decode(x.second).c_str(), sizeof(m_quote_body));            
        } else if (x.first == "platformInfoBlob") {
            platformInfoBlob = x.second;
        } else if (x.first == "fullResponse") {
            m_full_response = x.second;
        } else if (x.first == "x-iasreport-signature") {
            m_x_iasreport_signature = x.second;
        } else if (x.first == "x-iasreport-signing-certificate") {
            m_x_iasreport_signing_certificate = uriDecode(x.second);
        } else if (x.first == "location") {
            location = x.second;
        } else if (x.first == "revocationReason") {
            revocationReason = x.second;
        } else if (x.first == "pseManifestStatus") {
            pseManifestStatus = x.second;
        } else if (x.first == "pseManifestHash") { 
            pseManifestHash = x.second;
        } else if (x.first == "nonce") {
            nonce = x.second;
        } else if (x.first == "timestamp") {
            timestamp = x.second;
        }
    }

    if(!verifyCertificateChain()){
        Log("VerificationReport::fromResult - verifyCertificateChain failed");
        return false;
    }

    if(!verifySignature()) {
        Log("VerificationReport::fromResult - verifySignature failed");
        return false;
    }

    Log("VerificationReport::fromResult - success");
    return true;
}

string VerificationReport::uriDecode(string encoded){
    CURL *curl = curl_easy_init();
    int outlength;
    char *cres = curl_easy_unescape(curl, encoded.c_str(), encoded.length(), &outlength);
    std::string res(cres, cres + outlength);
    curl_free(cres);
    curl_easy_cleanup(curl);

    return res;
}

bool VerificationReport::verifyCertificateChain(){
    BIO              *certbio = NULL;
    BIO               *outbio = NULL;
    X509          *error_cert = NULL;
    X509_NAME    *certsubject = NULL;
    X509_STORE         *store = NULL;
    X509_STORE_CTX  *vrfy_ctx = NULL;
    int ret;
    bool func_ret = false;

    do {
        /* ---------------------------------------------------------- *
        * These function calls initialize openssl for correct work.  *
        * ---------------------------------------------------------- */
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        /* ---------------------------------------------------------- *
        * Create the Input/Output BIO's.                             *
        * ---------------------------------------------------------- */
        certbio = BIO_new(BIO_s_file());
        outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

        /* ---------------------------------------------------------- *
        * Initialize the global certificate validation store object. *
        * ---------------------------------------------------------- */
        if (!(store=X509_STORE_new())){
            Log("Error creating X509_STORE_CTX object\n");            
            break;
        }

        /* ---------------------------------------------------------- *
        * Create the context structure for the validation operation. *
        * ---------------------------------------------------------- */
        vrfy_ctx = X509_STORE_CTX_new();

        /* ---------------------------------------------------------- *
        * Load the certificate and cacert chain from file (PEM).     *
        * ---------------------------------------------------------- */
        certbio = BIO_new_mem_buf(m_x_iasreport_signing_certificate.c_str(), 
                                  m_x_iasreport_signing_certificate.length());
        if (!PEM_read_bio_X509(certbio, &m_cert, 0, NULL)) {
            Log("Error loading cert into memory\n");            
            break;
        }

        ret = X509_STORE_load_locations(store, Settings::ias_ca, NULL);
        if (ret != 1) {
            Log("Error loading CA cert or chain file\n");            
            break;
        }

        /* ---------------------------------------------------------- *
        * Initialize the ctx structure for a verification operation: *
        * Set the trusted cert store, the unvalidated cert, and any  *
        * potential certs that could be needed (here we set it NULL) *
        * ---------------------------------------------------------- */
        X509_STORE_CTX_init(vrfy_ctx, store, m_cert, NULL);

        /* ---------------------------------------------------------- *
        * Check the complete cert chain can be build and validated.  *
        * Returns 1 on success, 0 on verification failures, and -1   *
        * for trouble with the ctx object (i.e. missing certificate) *
        * ---------------------------------------------------------- */
        ret = X509_verify_cert(vrfy_ctx);  

        if(ret != 1)
        {
            Log("Verification return code: %d\n", ret);
            Log("Verification result text: %s\n", 
                X509_verify_cert_error_string(vrfy_ctx->error));            
            break;
        }

        func_ret = true;

    } while(0);

   /* ---------------------------------------------------------- *
    * Free up all structures                                     *
    * ---------------------------------------------------------- */
    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);
    BIO_free_all(certbio);
    BIO_free_all(outbio);

    if(!func_ret) return false;
    
    m_certificateValid = true;        
    
    Log("VerificationReport::verifyCertificateChain - success");
    return true;
}

bool VerificationReport::verifySignature() {

    if(!m_certificateValid){
        Log("VerificationReport::verifySignature - certificate invalid", log::error);
        return false;
    }

    EVP_PKEY* pkey = NULL;

    bool func_ret = false;

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
    if ((NULL == m_cert)  || (NULL == (pkey = X509_get_pubkey(m_cert))) ) {
        Log("Error getting public key from certificate");
        return false;
    }
    BIO* outbio = NULL;
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    PEM_write_bio_PUBKEY(outbio, pkey);

    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            Log("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_sha256();
        assert(md != NULL);
        if(md == NULL) {
            Log("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        if(rc != 1) {
            Log("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestUpdate(ctx, (const byte*)m_full_response.c_str(), 
                                    m_full_response.length());

        Log("report len %d", m_full_response.length());

        cout << m_full_response << "\n";
        cout << m_x_iasreport_signature << "\n";

        if(rc != 1) {
            Log("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_VerifyFinal(ctx, 
                        (const byte*)base64_decode(m_x_iasreport_signature).c_str(), 
                        SIGNATURE_LENGTH_BYTES,
                        pkey);
        
        if(rc != 1) {
            Log("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        func_ret = true;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    if(!func_ret) return false;

    //Once the signature is valid, the verification report is valid
    m_isValid = true;
    
    Log("VerificationReport::verifySignature - success");
    return func_ret;
}


bool VerificationReport::insertIASCertificate(Messages::CertificateMSG& certMsg){
    if(!m_isValid){
        Log("VerificationReport::insertIASCertificate - report invalid", log::error);
        return false;
    }
    
    certMsg.set_cert_size(m_x_iasreport_signing_certificate.length());

    for (int i=0; i< m_x_iasreport_signing_certificate.length(); i++)
        certMsg.add_x_iasreport_signing_certificate(m_x_iasreport_signing_certificate.c_str()[i]);

    Log("VerificationReport::insertIASCertificate - success");
    return true;
}

bool VerificationReport::insertIASSignature(Messages::CertificateMSG& certMsg){
    if(!m_isValid){
        Log("VerificationReport::insertIASCertificate - report invalid", log::error);
        return false;
    }

    certMsg.set_sig_size(m_x_iasreport_signature.length());

    for (int i=0; i< m_x_iasreport_signature.length(); i++)
        certMsg.add_x_iasreport_signature(m_x_iasreport_signature.c_str()[i]);

    Log("VerificationReport::insertIASSignature - success");
    return true;
}

bool VerificationReport::insertIASFullResponse(Messages::CertificateMSG& certMsg){
    if(!m_isValid){
        Log("VerificationReport::insertIASCertificate - report invalid", log::error);
        return false;
    }

    certMsg.set_response_size(m_full_response.length());

    for (int i=0; i< m_full_response.length(); i++)
        certMsg.add_full_response(m_full_response.c_str()[i]);

    Log("VerificationReport::insertIASFullResponse - success");
    return true;
}

bool VerificationReport::insertGa(Messages::CertificateMSG& certMsg){

    if(!m_isValid){
        Log("VerificationReport::insertGa - report invalid", log::error);
        return false;
    }

    for (auto x : m_ga.gx)
        certMsg.add_gax(x);

    for (auto x : m_ga.gy)
        certMsg.add_gay(x);

    Log("VerificationReport::insertGa - success");
    return true;
}

bool VerificationReport::extractIASCertificate(Messages::CertificateMSG& msg){
    if(m_isValid){
        Log("VerificationReport::extractIASCertificate - already valid", log::error);
        return false;
    }

    int certSize = msg.cert_size();
    char* certBuf = (char*)malloc(certSize);

    if(NULL == certBuf){
        Log("VerificationReport::extractIASSignature - failed to allocate mem for cert", log::error);
        return false;
    }

    for (int i = 0; i < certSize; i++){
        certBuf[i] = msg.x_iasreport_signing_certificate(i);
    }

    string certString(certBuf, certSize);
    m_x_iasreport_signing_certificate = certString;

    free(certBuf);

    Log("VerificationReport::extractIASCertificate - success");
    return true;
}

bool VerificationReport::extractIASSignature(Messages::CertificateMSG& msg){
    if(m_isValid){
        Log("VerificationReport::extractIASSignature - already valid", log::error);
        return false;
    }

    int signatureSize = msg.sig_size();
    char* signatureBuf = (char*)malloc(signatureSize);

    if(NULL == signatureBuf){
        Log("VerificationReport::extractIASSignature - failed to allocate mem for signature", log::error);
        return false;
    }

    for (int i = 0; i < signatureSize; i++){
        signatureBuf[i] = msg.x_iasreport_signature(i);
    }

    string signatureString(signatureBuf, signatureSize);
    m_x_iasreport_signature = signatureString;

    free(signatureBuf);

    Log("VerificationReport::extractIASSignature - success");
    return true;
}

bool VerificationReport::extractIASFullResponse(Messages::CertificateMSG& msg){
    if(m_isValid){
        Log("VerificationReport::extractIASFullResponse - already valid", log::error);
        return false;
    }

    int fullResponseSize = msg.response_size();
    char* fullResponseBuf = (char*)malloc(fullResponseSize);

    if(NULL == fullResponseBuf){
        Log("VerificationReport::extractIASFullResponse - failed to allocate mem for full response", log::error);
        return false;
    }

    for (int i = 0; i < fullResponseSize; i++){
        fullResponseBuf[i] = msg.full_response(i);
    }

    string fullResponseString(fullResponseBuf, fullResponseSize);
    m_full_response = fullResponseString;

    free(fullResponseBuf);

    Log("VerificationReport::extractIASFullResponse - success");
    return true;
}

bool VerificationReport::extractGa(Messages::CertificateMSG& certMsg){
  
    if(m_isValid){
        Log("VerificationReport::extractGa - already valid", log::error);
        return false;
    }

    for (int i=0; i< SGX_ECP256_KEY_SIZE; i++) {
        m_ga.gx[i] = certMsg.gax(i);
        m_ga.gy[i] = certMsg.gay(i);
    }

    Log("VerificationReport::extractGa - success");
    return true;
}