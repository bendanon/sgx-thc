#include "AttestationClient.h"
#include "sample_libcrypto.h"

using namespace util;

AttestationClient::AttestationClient(Enclave *enclave, 
                                     VerificationReport& report, 
                                     sgx_ec256_public_t* p_pk) : m_report(report) {
    if(enclave == NULL)
        Log("AttestationClient created with NULL enclave, should crash");
    
    if(p_pk == NULL)
        Log("AttestationClient created with NULL p_pk, should crash");

    this->nm = NetworkManagerClient::getInstance(Settings::rh_port, Settings::rh_host);
    this->ws = WebService::getInstance();
    m_pEnclave = enclave;
    m_p_pk = p_pk;
}

AttestationClient::~AttestationClient() { }


int AttestationClient::init() {
    this->nm->Init();
    this->ws->init();
    this->nm->connectCallbackHandler([this](string v, int type) {
        return this->incomingHandler(v, type);
    });
}


bool AttestationClient::sp_ra_proc_msg1_req(Messages::MessageMSG1 msg1, Messages::MessageMSG2 *msg2) {
    ra_samp_response_header_t **pp_msg2;
    bool func_ret = true;
    ra_samp_response_header_t* p_msg2_full = NULL;
    sgx_ra_msg2_t *p_msg2 = NULL;
    sample_ecc_state_handle_t ecc_state = NULL;
    sample_status_t sample_ret = SAMPLE_SUCCESS;
    bool derive_ret = false;

    do {

        //=====================  RETRIEVE SIGRL FROM IAS =======================        
        uint8_t GID[4];

        for (int i=0; i<4; i++)
            GID[i] = msg1.gid(i);

        reverse(begin(GID), end(GID));

        string sigRl;   

        if (!this->ws->getSigRL(ByteArrayToString(GID, 4), &sigRl)){
            Log("sp_ra_proc_msg1_req - getSigRL failed");
            return false;
        }
        Log("AttestationClient::sp_ra_proc_msg1_req - getSigRL success");       

        uint8_t *sig_rl;
        uint32_t sig_rl_size = StringToByteArray(sigRl, &sig_rl);        
        //=====================================================================

        uint8_t gaXLittleEndian[32];
        uint8_t gaYLittleEndian[32];

        for (int i=0; i<32; i++) {
            gaXLittleEndian[i] = msg1.gax(i);
            gaYLittleEndian[i] = msg1.gay(i);
        }

        sgx_ec256_public_t client_pub_key = {{0},{0}};

        for (int x=0; x<DH_SHARED_KEY_LEN; x++) {
            client_pub_key.gx[x] = gaXLittleEndian[x];
            client_pub_key.gy[x] = gaYLittleEndian[x];
        }


        sgx_status_t sgx_ret;
        sgx_ret = m_pEnclave->deriveSmk(&client_pub_key, sizeof(sgx_ec256_public_t),
                                        &m_smk_key, sizeof(sgx_ec_key_128bit_t));
        
        if(sgx_ret != SGX_SUCCESS){
            Log("AttestationClient::sp_ra_proc_msg1_req - deriveSmk failed", log::error);
            return false;
        }

        

        uint32_t msg2_size = sizeof(sgx_ra_msg2_t) + sig_rl_size;
        p_msg2_full = (ra_samp_response_header_t*)malloc(msg2_size + sizeof(ra_samp_response_header_t));

        if (!p_msg2_full) {
            Log("Error, Error, out of memory", log::error);
            func_ret = false;
            break;
        }

        memset(p_msg2_full, 0, msg2_size + sizeof(ra_samp_response_header_t));
        p_msg2_full->type = RA_MSG2;
        p_msg2_full->size = msg2_size;

        p_msg2_full->status[0] = 0;
        p_msg2_full->status[1] = 0;
        p_msg2 = (sgx_ra_msg2_t *) p_msg2_full->body;


        uint8_t *spidBa;
        HexStringToByteArray(Settings::spid, &spidBa);

        for (int i=0; i<16; i++)
            p_msg2->spid.id[i] = spidBa[i];


        // Assemble MSG2
        memcpy(&p_msg2->g_b, m_p_pk, sizeof(sgx_ec256_public_t));

        p_msg2->quote_type = SAMPLE_QUOTE_UNLINKABLE_SIGNATURE;
        p_msg2->kdf_id = AES_CMAC_KDF_ID;

        // Create gb_ga
        sgx_ec256_public_t gb_ga[2];
        memcpy(&gb_ga[0], m_p_pk, sizeof(sgx_ec256_public_t));
        memcpy(&gb_ga[1], &client_pub_key, sizeof(client_pub_key));
        
         // Generate the Service providers ECCDH key pair.
        sample_ret = sample_ecc256_open_context(&ecc_state);
        if(SAMPLE_SUCCESS != sample_ret) {
            Log("Error, cannot get ECC context", log::error);
            break;
        }

        // Sign gb_ga
        sample_ret = sample_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga),
                                       (sample_ec256_private_t *)&Settings::sp_priv_key,
                                       (sample_ec256_signature_t *)&p_msg2->sign_gb_ga,
                                       ecc_state);

        if (SAMPLE_SUCCESS != sample_ret) {
            Log("Error, sign ga_gb fail", log::error);
            func_ret = false;
            break;
        }

        // Generate the CMACsmk for gb||SPID||TYPE||KDF_ID||Sigsp(gb,ga)
        uint8_t mac[EC_MAC_SIZE] = {0};
        uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
        sample_ret = sample_rijndael128_cmac_msg(&m_smk_key, 
                                          (uint8_t *)&p_msg2->g_b, 
                                          cmac_size, &mac);

        if (SAMPLE_SUCCESS != sample_ret) {
            Log("Error, cmac fail", log::error);
            func_ret = false;
            break;
        }

        memcpy(&p_msg2->mac, mac, sizeof(mac));
        memcpy(&p_msg2->sig_rl[0], sig_rl, sig_rl_size);
        
        p_msg2->sig_rl_size = sig_rl_size;
        
    } while(0);

    if (!func_ret) {
        *pp_msg2 = NULL;
        SafeFree(p_msg2_full);
    } else {

        //=================   SET MSG2 Fields   ================
        msg2->set_type(RA_MSG2);

        msg2->set_size(p_msg2_full->size);

        for (auto x : p_msg2->g_b.gx)
            msg2->add_public_key_gx(x);

        for (auto x : p_msg2->g_b.gy)
            msg2->add_public_key_gy(x);

        for (auto x : p_msg2->spid.id)
            msg2->add_spid(x);

        msg2->set_quote_type(SAMPLE_QUOTE_UNLINKABLE_SIGNATURE);
        msg2->set_cmac_kdf_id(AES_CMAC_KDF_ID);

        for (auto x : p_msg2->sign_gb_ga.x) {
            msg2->add_signature_x(x);
        }

        for (auto x : p_msg2->sign_gb_ga.y)
            msg2->add_signature_y(x);

        for (auto x : p_msg2->mac)
            msg2->add_smac(x);

        msg2->set_size_sigrl(p_msg2->sig_rl_size);

        for (int i=0; i<p_msg2->sig_rl_size; i++)
            msg2->add_sigrl(p_msg2->sig_rl[i]);
        //=====================================================
    }

    if (ecc_state) {
        sample_ecc256_close_context(ecc_state);
    }

    return func_ret;
}


sgx_ra_msg3_t* AttestationClient::assembleMSG3(Messages::MessageMSG3 msg){
    sgx_ra_msg3_t *p_msg3 = (sgx_ra_msg3_t*) malloc(msg.size());

    for (int i=0; i<SGX_MAC_SIZE; i++)
        p_msg3->mac[i] = msg.sgx_mac(i);

    for (int i=0; i<SGX_ECP256_KEY_SIZE; i++) {
        p_msg3->g_a.gx[i] = msg.gax_msg3(i);
        p_msg3->g_a.gy[i] = msg.gay_msg3(i);
    }

    for (int i=0; i<256; i++)
        p_msg3->ps_sec_prop.sgx_ps_sec_prop_desc[i] = msg.sec_property(i);
    for (int i=0; i<1116; i++)
        p_msg3->quote[i] = msg.quote(i);

    return p_msg3;
}

bool AttestationClient::sp_ra_proc_msg3_req(Messages::MessageMSG3 msg){

    bool func_ret = true;
    sgx_ra_msg3_t *p_msg3 = NULL;

    p_msg3 = assembleMSG3(msg);

    memcpy(&m_ps_sec_prop, &p_msg3->ps_sec_prop, sizeof(p_msg3->ps_sec_prop));

    vector<pair<string, string>> result;
    if(!this->ws->verifyQuote(p_msg3->quote, 
                                p_msg3->ps_sec_prop.sgx_ps_sec_prop_desc, 
                                NULL, 
                                &result)) 
    {
        Log("Error, verifyQuote failed", log::error);
        return false;      
    }

    if(!m_report.fromResult(result)){
        Log("AttestationClient::sp_ra_proc_msg3_req failed generate valid report from IAS verification report");
        return false;
    }

    return true;
}

void AttestationClient::start() {
    
    /*MSG0 client-->server*/
    if(SGX_SUCCESS !=  getExtendedEPID_GID(&m_extended_epid_group_id)) {
        Log("AttestationClient::start - failed to getExtendedEPID_GID");
        return;
    }

    if (SGX_SUCCESS != m_pEnclave->initRa() || 
        SGX_SUCCESS != this->getEnclaveStatus()) {
        Log("Error, call enclave_init_ra fail", log::error);
        return;
    }

    bool ret = false;

    /*MSG1 client-->server*/
    string msg1_str = generateMSG1();
    Messages::MessageMSG1 msg1;
    ret = msg1.ParseFromString(msg1_str);

    if (!ret || (msg1.type() != RA_MSG1)) {
        Log("failed to generate MSG1");
        return;
    }

    /*MSG2 server-->client*/
    Messages::MessageMSG2 msg2;
    if(!sp_ra_proc_msg1_req(msg1, &msg2)){
        Log("failed to generate MSG2");
        return;
    }

    /*MSG3 client-->server*/
    Messages::MessageMSG3 msg3;
    string msg3_str = handleMSG2(msg2);

    ret = msg3.ParseFromString(msg3_str);

    if (!ret || (msg3.type() != RA_MSG3)) {
        Log("failed to generate MSG3");
        return;
    }

    if(!sp_ra_proc_msg3_req(msg3)){
        Log("failed to process MSG3");
        return;
    }

    //this->nm->startService();
}   

sgx_status_t AttestationClient::getEnclaveStatus() {
    return this->m_pEnclave->getStatus();
}


uint32_t AttestationClient::getExtendedEPID_GID(uint32_t *extended_epid_group_id) {
    
    int ret = sgx_get_extended_epid_group_id(extended_epid_group_id);

    if (SGX_SUCCESS != ret) {
        Log("Error, call sgx_get_extended_epid_group_id fail: 0x%x", ret);
        print_error_message((sgx_status_t)ret);
        return ret;
    } else
        Log("Call sgx_get_extended_epid_group_id success");

    return ret;
}


string AttestationClient::generateMSG0() {
    Log("Call MSG0 generate");

    uint32_t extended_epid_group_id;
    int ret = this->getExtendedEPID_GID(&extended_epid_group_id);

    Messages::MessageMsg0 msg;
    msg.set_type(RA_MSG0);

    if (ret == SGX_SUCCESS) {
        msg.set_epid(extended_epid_group_id);
    } else {
        msg.set_status(TYPE_TERMINATE);
        msg.set_epid(0);
    }
    return nm->serialize(msg);
}


string AttestationClient::generateMSG1() {
    int retGIDStatus = 0;
    int count = 0;
    sgx_ra_msg1_t sgxMsg1Obj;

    while (1) {
        retGIDStatus = sgx_ra_get_msg1(this->m_pEnclave->getContext(),
                                       this->m_pEnclave->getID(),
                                       sgx_ra_get_ga,
                                       &sgxMsg1Obj);

        if (retGIDStatus == SGX_SUCCESS) {
            break;
        } else if (retGIDStatus == SGX_ERROR_BUSY) {
            if (count == 5) { //retried 5 times, so fail out
                Log("AttestationClient::generateMSG1, sgx_ra_get_msg1 is busy - 5 retries failed", log::error);
                break;;
            } else {
                sleep(3);
                count++;
            }
        } else {    //error other than busy
            Log("AttestationClient::generateMSG1, failed to generate MSG1, error is %d", retGIDStatus);
            break;
        }
    }


    if (SGX_SUCCESS == retGIDStatus) {
        Log("MSG1 generated Successfully");

        Messages::MessageMSG1 msg;
        msg.set_type(RA_MSG1);

        for (auto x : sgxMsg1Obj.g_a.gx)
            msg.add_gax(x);

        for (auto x : sgxMsg1Obj.g_a.gy)
            msg.add_gay(x);

        for (auto x : sgxMsg1Obj.gid) {
            msg.add_gid(x);
        }

        return nm->serialize(msg);
    }

    return "";
}


void AttestationClient::assembleMSG2(Messages::MessageMSG2 msg, sgx_ra_msg2_t **pp_msg2) {
    uint32_t size = msg.size();

    sgx_ra_msg2_t *p_msg2 = NULL;
    p_msg2 = (sgx_ra_msg2_t*) malloc(size + sizeof(sgx_ra_msg2_t));

    uint8_t pub_key_gx[32];
    uint8_t pub_key_gy[32];

    sgx_ec256_signature_t sign_gb_ga;
    sgx_spid_t spid;

    for (int i; i<32; i++) {
        pub_key_gx[i] = msg.public_key_gx(i);
        pub_key_gy[i] = msg.public_key_gy(i);
    }

    for (int i=0; i<16; i++) {
        spid.id[i] = msg.spid(i);
    }

    for (int i=0; i<8; i++) {
        sign_gb_ga.x[i] = msg.signature_x(i);
        sign_gb_ga.y[i] = msg.signature_y(i);
    }

    memcpy(&p_msg2->g_b.gx, &pub_key_gx, sizeof(pub_key_gx));
    memcpy(&p_msg2->g_b.gy, &pub_key_gy, sizeof(pub_key_gy));
    memcpy(&p_msg2->sign_gb_ga, &sign_gb_ga, sizeof(sign_gb_ga));
    memcpy(&p_msg2->spid, &spid, sizeof(spid));

    p_msg2->quote_type = (uint16_t)msg.quote_type();
    p_msg2->kdf_id = msg.cmac_kdf_id();

    uint8_t smac[16];
    for (int i=0; i<16; i++)
        smac[i] = msg.smac(i);

    memcpy(&p_msg2->mac, &smac, sizeof(smac));

    p_msg2->sig_rl_size = msg.size_sigrl();
    uint8_t *sigrl = (uint8_t*) malloc(sizeof(uint8_t) * msg.size_sigrl());

    for (int i=0; i<msg.size_sigrl(); i++)
        sigrl[i] = msg.sigrl(i);

    memcpy(&p_msg2->sig_rl, &sigrl, msg.size_sigrl());

    *pp_msg2 = p_msg2;
}


string AttestationClient::handleMSG2(Messages::MessageMSG2 msg) {
    Log("Received MSG2");

    uint32_t size = msg.size();

    sgx_ra_msg2_t *p_msg2;
    this->assembleMSG2(msg, &p_msg2);

    sgx_ra_msg3_t *p_msg3 = NULL;
    uint32_t msg3_size;
    int ret = 0;

    do {
        ret = sgx_ra_proc_msg2(this->m_pEnclave->getContext(),
                               this->m_pEnclave->getID(),
                               sgx_ra_proc_msg2_trusted,
                               sgx_ra_get_msg3_trusted,
                               p_msg2,
                               size,
                               &p_msg3,
                               &msg3_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    m_pEnclave->closeRa();

    SafeFree(p_msg2);

    if (SGX_SUCCESS != (sgx_status_t)ret) {
        Log("Error, call sgx_ra_proc_msg2 fail, error code: 0x%x", ret);
    } else {
        Log("Call sgx_ra_proc_msg2 success");

        Messages::MessageMSG3 msg3;

        msg3.set_type(RA_MSG3);
        msg3.set_size(msg3_size);

        for (int i=0; i<SGX_MAC_SIZE; i++)
            msg3.add_sgx_mac(p_msg3->mac[i]);

        for (int i=0; i<SGX_ECP256_KEY_SIZE; i++) {
            msg3.add_gax_msg3(p_msg3->g_a.gx[i]);
            msg3.add_gay_msg3(p_msg3->g_a.gy[i]);
        }

        for (int i=0; i<256; i++) {
            msg3.add_sec_property(p_msg3->ps_sec_prop.sgx_ps_sec_prop_desc[i]);
        }


        for (int i=0; i<1116; i++) {
            msg3.add_quote(p_msg3->quote[i]);
        }

        SafeFree(p_msg3);
        return nm->serialize(msg3);
    }

    SafeFree(p_msg3);

    return "";
}

string AttestationClient::handleMSG4(Messages::MessageMSG4 msg){

    if(!m_report.fromMsg4(msg))
    {
        Log("failed to parse report from msg4", log::error);
         return "";
    }   

    Messages::InitialMessage response;
    response.set_type(RA_APP_ATT_OK);
    response.set_size(0);
    Log("AttestationClient::handleMSG4 - success");
    return nm->serialize(response);   
}

string AttestationClient::handleMSG0Response(Messages::MessageMsg0 msg) {
    Log("MSG0 response received");

    if (msg.status() == TYPE_OK) {
        sgx_status_t ret = m_pEnclave->initRa();

        if (SGX_SUCCESS != ret || this->getEnclaveStatus()) {
            Log("Error, call enclave_init_ra fail", log::error);
        } else {
            Log("Call enclave_init_ra success");
            Log("Sending msg1 to remote attestation service provider. Expecting msg2 back");

            auto ret = this->generateMSG1();

            return ret;
        }

    } else {
        Log("MSG0 response status was not OK", log::error);
    }

    return "";
}


/*
string AttestationClient::createInitMsg(int type, string msg) {
    Messages::SecretMessage init_msg;
    init_msg.set_type(type);
    init_msg.set_size(msg.size());

    return nm->serialize(init_msg);
}
*/


void AttestationClient::restart(){
    m_pEnclave->closeRa();
}

vector<string> AttestationClient::incomingHandler(string v, int type) {
    vector<string> res;
    string s;
    bool ret;

    if(type == RA_FAILED_READ)
    {
        Log("AttestationClient::incomingHandler - Failed read, restarting");
        restart();
        return res;
    }

    if (!v.empty()) {
        
        switch (type) {        
        case RA_MSG0: {		//MSG0 Response
            Messages::MessageMsg0 msg0;
            ret = msg0.ParseFromString(v);
            if (ret && (msg0.type() == RA_MSG0)) {
                s = this->handleMSG0Response(msg0);
                res.push_back(to_string(RA_MSG1));
            }
        }
        break;
        case RA_MSG2: {		//MSG2
            Messages::MessageMSG2 msg2;
            ret = msg2.ParseFromString(v);
            if (ret && (msg2.type() == RA_MSG2)) {
                s = this->handleMSG2(msg2);
                res.push_back(to_string(RA_MSG3));
            }
        }
        break;
        case RA_ATT_RESULT: {	//MSG4
            Messages::MessageMSG4 att_msg;
            ret = att_msg.ParseFromString(v);
            if (ret && att_msg.type() == RA_ATT_RESULT) {
                //s = this->handleAttestationResult(att_msg);
                s = this->handleMSG4(att_msg);
                res.push_back(to_string(RA_APP_ATT_OK));
            }
        }
        break;
        default:
            Log("Unknown type: %d", type, log::error);
            break;
        }
    } else {
        s = this->generateMSG0();
        res.push_back(to_string(RA_MSG0));      
    }

    res.push_back(s);

    return res;
}


















