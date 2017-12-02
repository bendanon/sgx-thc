#include "VerificationReport.h"

 const char VerificationReport::dummy_cert_buf[] = "-----BEGIN CERTIFICATE-----\n"
  "MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n"
  "BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\n"
  "BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\n"
  "YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\n"
  "MDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\n"
  "bnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\n"
  "SW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\n"
  "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\n"
  "beCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\n"
  "cv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\n"
  "LUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\n"
  "ImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\n"
  "gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\n"
  "MB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\n"
  "wDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\n"
  "c2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\n"
  "cG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\n"
  "Rq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\n"
  "lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\n"
  "WLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\n"
  "ZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\n"
  "6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\n"
  "2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\n"
  "tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\n"
  "d4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\n"
  "-----END CERTIFICATE-----\n"
  "-----BEGIN CERTIFICATE-----\n"
  "MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n"
  "BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\n"
  "BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\n"
  "YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\n"
  "MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\n"
  "U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\n"
  "DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\n"
  "CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\n"
  "LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\n"
  "rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\n"
  "L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\n"
  "NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\n"
  "byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\n"
  "afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n"
  "6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\n"
  "RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\n"
  "MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\n"
  "L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\n"
  "BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\n"
  "NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\n"
  "hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\n"
  "IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\n"
  "sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\n"
  "zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\n"
  "Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n"
  "152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n"
  "3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\n"
  "DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\n"
  "DaVzWh5aiEx+idkSGMnX\n"
  "-----END CERTIFICATE-----";

VerificationReport::VerificationReport() : m_isValid(false) 
{ 
    memset(&m_quote_body, 0, sizeof(m_quote_body));
}
VerificationReport::~VerificationReport() { 
    X509_free(m_cert);
}

bool VerificationReport::deserialize(uint8_t* buffer) {
    Log("VerificationReport::deserialize - not implemented");
    return false;
}

bool VerificationReport::serialize(uint8_t* o_buffer){
    Log("VerificationReport::serialize - not implemented");
    return false;
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
            m_x_iasreport_signature = Base64decode(x.second);
        } else if (x.first == "x-iasreport-signing-certificate") {
            m_x_iasreport_signing_certificate = x.second;
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

    m_isValid = verifySignature();

    Log("VerificationReport::fromResult - success");
    return true;
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
        certbio = BIO_new_mem_buf(dummy_cert_buf, sizeof(dummy_cert_buf));
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
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
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
        
        rc = EVP_DigestVerifyUpdate(ctx, (const byte*)msg_dummy, mlen);
        if(rc != 1) {
            Log("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        /* Clear any errors for the call below */
        ERR_clear_error();
        
        rc = EVP_DigestVerifyFinal(ctx, 
                                  (const byte*)base64_decode(sig_base64_dummy).c_str(), 
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