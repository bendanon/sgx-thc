#include "ServiceProvider.h"
#include "sample_libcrypto.h"
#include "../GeneralSettings.h"

ServiceProvider::ServiceProvider(WebService *ws) : ws(ws) {}

ServiceProvider::~ServiceProvider() {}


int ServiceProvider::sp_ra_proc_msg0_req(const uint32_t id) {

    //This means we only support a single epid group id at a time.
    if(this->g_is_sp_registered && (id != this->extended_epid_group_id))
    {
        Log("Got msg0 request with id %d but a different id is already registered", id);
        return SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
    }

    Log("Received extended EPID group ID: %d", id);

    this->extended_epid_group_id = id;
    this->g_is_sp_registered = true; //TODO: falsify when session terminates

    return SP_OK;
}


int ServiceProvider::sp_ra_proc_msg1_req(Messages::MessageMSG1 msg1, Messages::MessageMSG2 *msg2) {
    ra_samp_response_header_t **pp_msg2;
    int ret = 0;
    ra_samp_response_header_t* p_msg2_full = NULL;
    sgx_ra_msg2_t *p_msg2 = NULL;
    sample_ecc_state_handle_t ecc_state = NULL;
    sample_status_t sample_ret = SAMPLE_SUCCESS;
    bool derive_ret = false;

    if (!g_is_sp_registered) {
        return SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
    }
    
    do {

        //=====================  RETRIEVE SIGRL FROM IAS =======================        
        uint8_t GID[4];

        for (int i=0; i<4; i++)
            GID[i] = msg1.gid(i);

        reverse(begin(GID), end(GID));

        string sigRl;
        bool error = false;
        #ifdef VERIFY_SIGRL
            error = this->ws->getSigRL(ByteArrayToString(GID, 4), &sigRl);
        #else
        sdf
            sigRl = "";
        #endif

        if (error)
            return SP_RETRIEVE_SIGRL_ERROR;

        uint8_t *sig_rl;
        uint32_t sig_rl_size = StringToByteArray(sigRl, &sig_rl);        
        //=====================================================================

        uint8_t gaXLittleEndian[32];
        uint8_t gaYLittleEndian[32];

        for (int i=0; i<32; i++) {
            gaXLittleEndian[i] = msg1.gax(i);
            gaYLittleEndian[i] = msg1.gay(i);
        }

        sample_ec256_public_t client_pub_key = {{0},{0}};

        for (int x=0; x<DH_SHARED_KEY_LEN; x++) {
            client_pub_key.gx[x] = gaXLittleEndian[x];
            client_pub_key.gy[x] = gaYLittleEndian[x];
        }

        // Need to save the client's public ECCDH key to local storage
        if (memcpy_s(&g_sp_db.g_a, sizeof(g_sp_db.g_a), &client_pub_key, sizeof(client_pub_key))) {
            Log("Error, cannot do memcpy", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the Service providers ECCDH key pair.
        sample_ret = sample_ecc256_open_context(&ecc_state);
        if(SAMPLE_SUCCESS != sample_ret) {
            Log("Error, cannot get ECC context", log::error);
            ret = -1;
            break;
        }


        sample_ec256_public_t pub_key = {{0},{0}};
        sample_ec256_private_t priv_key = {{0}};
        sample_ret = sample_ecc256_create_key_pair(&priv_key, &pub_key, ecc_state);

        if (SAMPLE_SUCCESS != sample_ret) {
            Log("Error, cannot get key pair", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Need to save the SP ECCDH key pair to local storage.
        if (memcpy_s(&g_sp_db.b, sizeof(g_sp_db.b), &priv_key,sizeof(priv_key)) ||
                memcpy_s(&g_sp_db.g_b, sizeof(g_sp_db.g_b), &pub_key,sizeof(pub_key))) {
            Log("Error, cannot do memcpy", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the client/SP shared secret
        sample_ec_dh_shared_t dh_key = {{0}};

        sample_ret = sample_ecc256_compute_shared_dhkey(&priv_key, (sample_ec256_public_t *)&client_pub_key,
                     (sample_ec256_dh_shared_t *)&dh_key,
                     ecc_state);

        if (SAMPLE_SUCCESS != sample_ret) {
            Log("Error, compute share key fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        #ifndef SUPPLIED_KEY_DERIVATION        
        // smk is only needed for msg2 generation.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK, &g_sp_db.smk_key);
        if (derive_ret != true) {
            Log("Error, derive key fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK, &g_sp_db.mk_key);
        if (derive_ret != true) {
            Log("Error, derive key fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SK, &g_sp_db.sk_key);
        if (derive_ret != true) {
            Log("Error, derive key fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_VK, &g_sp_db.vk_key);
        if (derive_ret != true) {
            Log("Error, derive key fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        
        #else

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK_SK, &g_sp_db.smk_key, &g_sp_db.sk_key);
        if (derive_ret != true) {
            Log("Error, derive key fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK_VK, &g_sp_db.mk_key, &g_sp_db.vk_key);
        if (derive_ret != true) {
            Log("Error, derive key fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        #endif

        uint32_t msg2_size = sizeof(sgx_ra_msg2_t) + sig_rl_size;
        p_msg2_full = (ra_samp_response_header_t*)malloc(msg2_size + sizeof(ra_samp_response_header_t));

        if (!p_msg2_full) {
            Log("Error, Error, out of memory", log::error);
            ret = SP_INTERNAL_ERROR;
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
        if(memcpy_s(&p_msg2->g_b, sizeof(p_msg2->g_b), &g_sp_db.g_b, sizeof(g_sp_db.g_b))) {
            Log("Error, memcpy failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        p_msg2->quote_type = SAMPLE_QUOTE_UNLINKABLE_SIGNATURE;
        p_msg2->kdf_id = AES_CMAC_KDF_ID;

        // Create gb_ga
        sgx_ec256_public_t gb_ga[2];
        if (memcpy_s(&gb_ga[0], sizeof(gb_ga[0]), &g_sp_db.g_b, sizeof(g_sp_db.g_b)) ||
                memcpy_s(&gb_ga[1], sizeof(gb_ga[1]), &g_sp_db.g_a, sizeof(g_sp_db.g_a))) {
            Log("Error, memcpy failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Sign gb_ga
        sample_ret = sample_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga),
                                       (sample_ec256_private_t *)&g_sp_priv_key,
                                       (sample_ec256_signature_t *)&p_msg2->sign_gb_ga,
                                       ecc_state);

        if (SAMPLE_SUCCESS != sample_ret) {
            Log("Error, sign ga_gb fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }


        // Generate the CMACsmk for gb||SPID||TYPE||KDF_ID||Sigsp(gb,ga)
        uint8_t mac[SAMPLE_EC_MAC_SIZE] = {0};
        uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.smk_key, (uint8_t *)&p_msg2->g_b, cmac_size, &mac);

        if (SAMPLE_SUCCESS != sample_ret) {
            Log("Error, cmac fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        if (memcpy_s(&p_msg2->mac, sizeof(p_msg2->mac), mac, sizeof(mac))) {
            Log("Error, memcpy failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

       
        if (memcpy_s(&p_msg2->sig_rl[0], sig_rl_size, sig_rl, sig_rl_size)) {
            Log("Error, memcpy failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        
        p_msg2->sig_rl_size = sig_rl_size;

    } while(0);
    


    if (ret) {
        *pp_msg2 = NULL;
        SafeFree(p_msg2_full);
    } else {

        //=================   SET MSG2 Fields   ================
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

    return ret;
}


sgx_ra_msg3_t* ServiceProvider::assembleMSG3(Messages::MessageMSG3 msg) {
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



// Process remote attestation message 3
int ServiceProvider::sp_ra_proc_msg3_req(Messages::MessageMSG3 msg, Messages::MessageMSG4& att_msg) {
    int ret = 0;
    sample_status_t sample_ret = SAMPLE_SUCCESS;
    const uint8_t *p_msg3_cmaced = NULL;
    sgx_quote_t *p_quote = NULL;
    sample_sha_state_handle_t sha_handle = NULL;
    sample_report_data_t report_data = {0};
    sample_ra_att_result_msg_t *p_att_result_msg = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    uint32_t i;
    sgx_ra_msg3_t *p_msg3 = NULL;
    uint32_t att_result_msg_size;
    int len_hmac_nonce = 0;

    p_msg3 = assembleMSG3(msg);

    // Check to see if we have registered?
    if (!g_is_sp_registered) {
        Log("Unsupported extended EPID group", log::error);
        return -1;
    }

    do {
        // Compare g_a in message 3 with local g_a.
        if (memcmp(&g_sp_db.g_a, &p_msg3->g_a, sizeof(sgx_ec256_public_t))) {
            Log("Error, g_a is not same", log::error);
            ret = SP_PROTOCOL_ERROR;
            break;
        }

        //Make sure that msg3_size is bigger than sample_mac_t.
        uint32_t mac_size = msg.size() - sizeof(sample_mac_t);
        p_msg3_cmaced = reinterpret_cast<const uint8_t*>(p_msg3);
        p_msg3_cmaced += sizeof(sample_mac_t);

        // Verify the message mac using SMK
        sample_cmac_128bit_tag_t mac = {0};
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.smk_key, p_msg3_cmaced, mac_size, &mac);

        if (SAMPLE_SUCCESS != sample_ret) {
            Log("Error, cmac fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        if (memcmp(&p_msg3->mac, mac, sizeof(mac))) {
            Log("Error, verify cmac fail", log::error);
            ret = SP_INTEGRITY_FAILED;
            break;
        }

        if (memcpy_s(&g_sp_db.ps_sec_prop, sizeof(g_sp_db.ps_sec_prop), &p_msg3->ps_sec_prop, sizeof(p_msg3->ps_sec_prop))) {
            Log("Error, memcpy fail", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        p_quote = (sgx_quote_t *) p_msg3->quote;


        // Verify the report_data in the Quote matches the expected value.
        // The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
        // The second 32 bytes of report_data are set to zero.
        sample_ret = sample_sha256_init(&sha_handle);
        if (sample_ret != SAMPLE_SUCCESS) {
            Log("Error, init hash failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_a), sizeof(g_sp_db.g_a), sha_handle);
        if (sample_ret != SAMPLE_SUCCESS) {
            Log("Error, udpate hash failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_b), sizeof(g_sp_db.g_b), sha_handle);
        if (sample_ret != SAMPLE_SUCCESS) {
            Log("Error, udpate hash failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        Log("vk is %s", Base64encodeUint8((uint8_t *)&g_sp_db.vk_key,sizeof(sgx_ec_key_128bit_t)));

        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.vk_key), sizeof(g_sp_db.vk_key), sha_handle);
        if (sample_ret != SAMPLE_SUCCESS) {
            Log("Error, udpate hash failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        sample_ret = sample_sha256_get_hash(sha_handle, (sample_sha256_hash_t *)&report_data);
        if (sample_ret != SAMPLE_SUCCESS) {
            Log("Error, Get hash failed", log::error);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        if (memcmp((uint8_t *)&report_data, (uint8_t *)&(p_quote->report_body.report_data), sizeof(report_data))) {
            Log("Error, verify hash failed", log::error);
            ret = SP_INTEGRITY_FAILED;
            break;
        }

        vector<pair<string, string>> result;
        bool error = this->ws->verifyQuote(p_msg3->quote, 
                                       p_msg3->ps_sec_prop.sgx_ps_sec_prop_desc, 
                                       NULL, 
                                       &result);

        if (error) {
            ret = SP_IAS_FAILED;
            break;
        }

        m_report.fromResult(result);
        bool pkvalid = m_report.verifyPublicKey(g_sp_db.g_a, g_sp_db.g_b);
        Log("pkvalid %s", pkvalid ? "TRUE" : "FALSE");
        assert(!pkvalid);

    }while(0);

    return ret;
}

