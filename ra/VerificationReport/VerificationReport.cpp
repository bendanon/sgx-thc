#include "VerificationReport.h"

VerificationReport::VerificationReport() : m_isValid(false) 
{ 
    memset(&m_quote_body, 0, sizeof(m_quote_body));
}
VerificationReport::~VerificationReport() { }

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

    m_isValid = verifySignature();

    Log("VerificationReport::fromResult - success");
    return true;
}

bool VerificationReport::verifySignature(){

  const char ca_bundlestr[] = "/etc/ssl/certs/ca-certificates.crt";

  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509          *error_cert = NULL;
  X509                *cert = NULL;
  X509_NAME    *certsubject = NULL;
  X509_STORE         *store = NULL;
  X509_STORE_CTX  *vrfy_ctx = NULL;
  int ret;

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
  if (!(store=X509_STORE_new()))
     BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");

  /* ---------------------------------------------------------- *
   * Create the context structure for the validation operation. *
   * ---------------------------------------------------------- */
  vrfy_ctx = X509_STORE_CTX_new();

  /* ---------------------------------------------------------- *
   * Load the certificate and cacert chain from file (PEM).     *
   * ---------------------------------------------------------- */
  certbio = BIO_new_mem_buf(const_cast<char*>(m_x_iasreport_signing_certificate.c_str()), 
                            m_x_iasreport_signing_certificate.length());
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    exit(-1);
  }

  ret = X509_STORE_load_locations(store, ca_bundlestr, NULL);
  if (ret != 1)
    BIO_printf(outbio, "Error loading CA cert or chain file\n");

  /* ---------------------------------------------------------- *
   * Initialize the ctx structure for a verification operation: *
   * Set the trusted cert store, the unvalidated cert, and any  *
   * potential certs that could be needed (here we set it NULL) *
   * ---------------------------------------------------------- */
  X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);

  /* ---------------------------------------------------------- *
   * Check the complete cert chain can be build and validated.  *
   * Returns 1 on success, 0 on verification failures, and -1   *
   * for trouble with the ctx object (i.e. missing certificate) *
   * ---------------------------------------------------------- */
  ret = X509_verify_cert(vrfy_ctx);
  BIO_printf(outbio, "Verification return code: %d\n", ret);

  if(ret == 0 || ret == 1)
  BIO_printf(outbio, "Verification result text: %s\n",
             X509_verify_cert_error_string(vrfy_ctx->error));

  /* ---------------------------------------------------------- *
   * The error handling below shows how to get failure details  *
   * from the offending certificate.                            *
   * ---------------------------------------------------------- */
  if(ret == 0) {
    /*  get the offending certificate causing the failure */
    error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
    certsubject = X509_NAME_new();
    certsubject = X509_get_subject_name(error_cert);
    BIO_printf(outbio, "Verification failed cert:\n");
    X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
    BIO_printf(outbio, "\n");
  }

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  X509_STORE_CTX_free(vrfy_ctx);
  X509_STORE_free(store);
  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
    Log("VerificationReport::verifySignature - not implemented");
    return false;
}