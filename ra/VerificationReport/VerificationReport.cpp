#include "VerificationReport.h"
#include "sample_libcrypto.h"

VerificationReport::VerificationReport() : m_isValid(false) 
{ 
    memset(&m_quote_body, 0, sizeof(m_quote_body));
}
VerificationReport::~VerificationReport() { 
    X509_free(m_cert);
}

bool VerificationReport::verifyPublicKey(sgx_ec256_public_t* p_ga, 
                                         sgx_ec256_public_t* p_gb){

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

    sample_ret = sample_sha256_update((uint8_t *)p_ga, sizeof(sgx_ec256_public_t), sha_handle);
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

bool VerificationReport::fromMsg4(Messages::MessageMSG4& msg) {

    //TODO - this should extract the whole response body and signature, 
    //not just report body

    uint32_t* response_body_buf = reinterpret_cast<uint32_t*>(&this->m_report_body);

    for (int i=0; i<sizeof(sgx_report_body_t)/sizeof(uint32_t); i++)
        response_body_buf[i] = msg.response_body(i);

    m_isValid=true; //TODO - this should not be the only condition for a valid report

    Log("VerificationReport::fromMsg4 - success");
    return true;
 }

 bool VerificationReport::read(std::string file){
    if(!readEncodedAssets(file, (uint8_t*)&this->m_report_body, 
                           sizeof(sgx_report_body_t), REPORT_BASE64_SIZE_BYTES))
    {
        Log("VerificationReport::read report failed");
        return false;
    }

    Log("VerificationReport::read - succeeded");
    return true;
 }

 bool VerificationReport::write(std::string file){

    if(!writeEncodedAssets(file, (uint8_t*)&this->m_report_body, 
                           sizeof(sgx_report_body_t), REPORT_BASE64_SIZE_BYTES))
    {
        Log("VerificationReport::write report failed");
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

    string isvEnclaveQuoteBody,
           platformInfoBlob, 
           revocationReason,
           pseManifestStatus,
           pseManifestHash,
           nonce,
           /*epidPseudonym*/
           timestamp;

    for (auto x : result) {
        if (x.first == "id") {
            m_id = x.second;
        } else if (x.first == "isvEnclaveQuoteStatus") {

            if (x.second == "OK")
                m_quoteStatus = IAS_QUOTE_OK;
            else if (x.second == "SIGNATURE_INVALID")
                m_quoteStatus = IAS_QUOTE_SIGNATURE_INVALID;
            else if (x.second == "GROUP_REVOKED")
                m_quoteStatus = IAS_QUOTE_GROUP_REVOKED;
            else if (x.second == "SIGNATURE_REVOKED")
                m_quoteStatus = IAS_QUOTE_SIGNATURE_REVOKED;
            else if (x.second == "KEY_REVOKED")
                m_quoteStatus = IAS_QUOTE_KEY_REVOKED;
            else if (x.second == "SIGRL_VERSION_MISMATCH")
                m_quoteStatus = IAS_QUOTE_SIGRL_VERSION_MISMATCH;
            else if (x.second == "GROUP_OUT_OF_DATE")
                m_quoteStatus = IAS_QUOTE_GROUP_OUT_OF_DATE;

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
            m_location = x.second;
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

    m_isValid = true;

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

    Log("VerificationReport::verifyCertificateChain - success");
    return func_ret;
}

bool VerificationReport::verifySignature() {

    EVP_PKEY* pkey = NULL;

    bool func_ret = false;

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
    if ((NULL == m_cert)  || (NULL == (pkey = X509_get_pubkey(m_cert))) ) {
        Log("Error getting public key from certificate");
        return false;
    }

    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            Log("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(HASH_ALGORITHM);
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
        
        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
        if(rc != 1) {
            Log("EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestVerifyUpdate(ctx, (const byte*)m_full_response.c_str(), 
                                    m_full_response.length());
        if(rc != 1) {
            Log("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        /* Clear any errors for the call below */
        ERR_clear_error();
        
        rc = EVP_DigestVerifyFinal(ctx, 
                        (const byte*)base64_decode(m_x_iasreport_signature).c_str(), 
                        SIGNATURE_LENGTH_BYTES);
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
    
    return func_ret;
}
