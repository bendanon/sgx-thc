#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include <cassert>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_uae_service.h"
#include "sgx_tseal.h"
#include <stdlib.h>
#include "sgx_utils.h"
#include "th_definitions.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    printf("SGX error code: %d\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
 int initialize_enclave(sgx_enclave_id_t* eid, const std::string& launch_token_path, const std::string& enclave_name) {
    const char* token_path = launch_token_path.c_str();
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    FILE* fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

sgx_status_t init_quote(sgx_target_info_t* p_target_info, sgx_quote_t** pp_quote, uint32_t* p_quote_size){

    sgx_status_t status;
    status = sgx_calc_quote_size(NULL, 0, p_quote_size);
    std::cout << "sgx_calc_quote_size status is " << status << " and result is " << *p_quote_size << std::endl;
    if(status) return status;

    *pp_quote = (sgx_quote_t*)malloc(*p_quote_size);
    memset(*pp_quote, 0 , *p_quote_size);    

    memset(p_target_info, 0 , sizeof(sgx_target_info_t));
    status = sgx_init_quote(p_target_info, &((*pp_quote)->epid_group_id));
    std::cout << "sgx_init_quote status is " << status << std::endl;
    if(status) return status;

    return SGX_SUCCESS;
}

sgx_status_t get_quote(sgx_report_t* p_report, sgx_quote_t* p_quote, uint32_t quote_size){
    sgx_status_t status;
    sgx_spid_t spid;
    memset(&spid, 1, sizeof(spid)); // can be my name..?

    status = sgx_get_quote(p_report,                     //const sgx_report_t *p_report            
                           SGX_UNLINKABLE_SIGNATURE,    //sgx_quote_sign_type_t quote_type
                           &spid,                       //const sgx_spid_t *p_spid       
                           NULL,                        //const sgx_quote_nonce_t *p_nonce
                           NULL,                        //const uint8_t *p_sig_rl
                           0,                           //uint32_t sig_rl_size
                           NULL,                        //sgx_report_t *p_qe_report
                           p_quote,                     //sgx_quote_t *p_quote
                           quote_size);                 //uint32_t quote_size

    std::cout <<"sgx_get_quote status is " << status << std::endl;

    return status;
}

/***
[Initialization: no input] - *SKG SERVER CODE*
1. Use SGX hardware randomness to generate shared secret key s
2. Generate an encryption key pair (pk,sk), output pk.
3. Use the "independent attestation" mechanism to generate an Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode". This is Q’, output.
4. Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data. output.
***/
sgx_status_t skg_initialization(sgx_ec256_public_t** pp_skg_pk, 
                                sgx_quote_t** pp_quote, 
                                sgx_sealed_data_t** pp_sealed_s_sk)
{

    //Sealed data structs
    sgx_sealed_data_t* _p_sealed_s_sk = (sgx_sealed_data_t*)malloc(SKG_DATA_SEALED_SIZE_BYTES);
    memset(_p_sealed_s_sk, 0, SKG_DATA_SEALED_SIZE_BYTES);
    _p_sealed_s_sk->key_request.key_policy = KEYPOLICY_MRENCLAVE;    

    //pk structs
    sgx_ec256_public_t* _p_skg_pk = (sgx_ec256_public_t*)malloc(sizeof(sgx_ec256_public_t));    
    size_t pk_size = sizeof(sgx_ec256_public_t);
    memset(_p_skg_pk, 0, pk_size);

    sgx_status_t status;

    //quote structs
    sgx_target_info_t target_info;
    sgx_quote_t* _p_quote;
    uint32_t quote_size;
    status = init_quote(&target_info, &_p_quote, &quote_size);
    std::cout << "init_quote status is " << status << std::endl;
    if(status) return status;
    
    sgx_report_t report;
    memset(&report, 0, sizeof(report));

    sgx_status_t retval;
    status = skg_init(global_eid, &retval, _p_sealed_s_sk, SKG_DATA_SEALED_SIZE_BYTES, _p_skg_pk, pk_size, &target_info, &report);

    std::cout << "skg_init status is " << status << " retval is " << retval << "." << std::endl;

    status = get_quote(&report, _p_quote, quote_size);
    std::cout <<"get_quote status is " << status << std::endl;    
    if(status) return status;

    *pp_sealed_s_sk = _p_sealed_s_sk;
    *pp_skg_pk = _p_skg_pk;
    *pp_quote = _p_quote; 
    
    return SGX_SUCCESS;
}

/***
[Initialization-step 1: input pk, attestation quote Q']
1. Verify that Q' is a valid Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode"
2. Use SGX hardware randomness to generate a symmetric encryption key k.
3. Compute c=E_pk(k)  --- the (public-key) encryption of k under pk
4. Use the "independent attestation" mechanism to generate an Intel-signed quote that "c was generated by [X-Black-Box Enclave] running in secure mode". This is Q, output.
5. Seal (k) [sealing to MRENCLAVE] and output c and sealed data.
***/
sgx_status_t bb_initialization_1(sgx_ec256_public_t* p_skg_pk,               //in
                                 sgx_quote_t* p_skg_quote,                   //in
                                 sgx_ec256_public_t** pp_bb_pk,                //out    
                                 sgx_sealed_data_t** pp_sealed_k,              //out
                                 sgx_quote_t** pp_bb_quote,                    //out
                                 uint8_t k_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES
                                ] //out
                                ){
    
    //Verify that Q' is a valid Intel-signed quote that 
    //"pk was generated by [Secret-Key-Generation Enclave] running in secure mode"
    
    //Sealed data structs
    sgx_sealed_data_t* _p_sealed_k = (sgx_sealed_data_t*)malloc(SECRET_KEY_SEALED_SIZE_BYTES);
    memset(_p_sealed_k, 0, SECRET_KEY_SEALED_SIZE_BYTES);
    _p_sealed_k->key_request.key_policy = KEYPOLICY_MRENCLAVE;    

    //pk structs
    sgx_ec256_public_t* _p_bb_pk = (sgx_ec256_public_t*)malloc(sizeof(sgx_ec256_public_t));    
    size_t pk_size = sizeof(sgx_ec256_public_t);
    memset(_p_bb_pk, 0, pk_size);
        
    sgx_status_t status;

    //quote structs
    sgx_target_info_t target_info;
    sgx_quote_t* _p_bb_quote;
    uint32_t quote_size;
    status = init_quote(&target_info, &_p_bb_quote, &quote_size);
    std::cout << "init_quote status is " << status << std::endl;
    if(status) return status;
    sgx_report_t report;
    memset(&report, 0, sizeof(report));
    
    sgx_status_t retval;
    status = bb_init_1(global_eid, &retval, _p_sealed_k, SECRET_KEY_SEALED_SIZE_BYTES, _p_bb_pk, p_skg_pk, pk_size, k_encrypted, SECRET_KEY_ENCRYPTED_SIZE_BYTES
    , &target_info, &report);

    std::cout << "bb_init_1 status is " << status << " retval is " << retval << "." << std::endl;

    status = get_quote(&report, _p_bb_quote, quote_size);
    std::cout <<"get_quote status is " << status << std::endl;    
    if(status) return status;

    *pp_sealed_k = _p_sealed_k;
    *pp_bb_pk = _p_bb_pk;
    *pp_bb_quote = _p_bb_quote;

    return SGX_SUCCESS;
}

/*
[Execution: input pk, sealed data (s,sk), ciphertext c, an attestation quote Q]
1. Verify that Q is a valid Intel-signed quote of the form "c was generated by [X-Black-Box Enclave] running in secure mode"
2. Unseal s,sk (verify that pk matches sk)
3. Decrypt c using sk to get a symmetric encryption key k
4. Compute and output c'=E_k(s) --- the (symmetric) encryption of s under k
*/
sgx_status_t skg_execution(sgx_ec256_public_t* p_bb_pk,                    //in
                           sgx_ec256_public_t* p_skg_pk,                   //in (pk)
                           uint8_t k_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES
                        ],    //in (c)
                           sgx_quote_t* p_bb_quote,                        //in (Q)
                           sgx_sealed_data_t* p_sealed_s_sk,               //in (Seal(s,sk))
                           uint8_t s_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES])    //out (c')
{
    //Verify that Q is a valid Intel-signed quote of the form "c was generated by 
    //[X-Black-Box Enclave] running in secure mode"

    sgx_status_t status;
    sgx_status_t retval;
    status = skg_exec(global_eid, &retval, 
                      p_bb_pk, p_skg_pk, sizeof(sgx_ec256_public_t),
                      k_encrypted, SECRET_KEY_ENCRYPTED_SIZE_BYTES,
                      p_sealed_s_sk, SKG_DATA_SEALED_SIZE_BYTES, 
                      s_encrypted, SECRET_KEY_ENCRYPTED_SIZE_BYTES);
    
    std::cout << "skg_exec status is " << status << " retval is " << retval << "." << std::endl;
    
    return status;
}

/***
[Initialization-step 2: input sealed data (k), ciphertext c']
1. Unseal k
2. Decrypt c' with k to get s
3. Seal (s) [to MRENCLAVE] and output sealed data.
***/
sgx_status_t bb_initialization_2(sgx_sealed_data_t* p_sealed_k,                         //in (Seal(k))
                                 uint8_t s_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES],  //in (c')
                                 sgx_sealed_data_t** pp_sealed_s)                         //out (Seal(s))
{
    sgx_status_t status;
    sgx_status_t retval;

    //Sealed data structs
    sgx_sealed_data_t* _p_sealed_s = (sgx_sealed_data_t*)malloc(SECRET_KEY_SEALED_SIZE_BYTES);
    memset(_p_sealed_s, 0, SECRET_KEY_SEALED_SIZE_BYTES);
    _p_sealed_s->key_request.key_policy = KEYPOLICY_MRENCLAVE;

    status = bb_init_2(global_eid, &retval, 
                       p_sealed_k,
                       s_encrypted, SECRET_KEY_ENCRYPTED_SIZE_BYTES,
                       _p_sealed_s, SECRET_KEY_SEALED_SIZE_BYTES);
                       
    std::cout << "bb_init_2 status is " << status << " retval is " << retval << "." << std::endl;
                 
    *pp_sealed_s = _p_sealed_s;
    return status;
}

/*
[Execution: input sealed data (s), memory buffer B_in]
1. Unseal s
2. Execute B_out=X_s(B_in)
3. Output B_out
*/
sgx_status_t bb_execution(sgx_sealed_data_t* p_sealed_s,    //in (Seal(s))
                          uint8_t B_in[B_IN_SIZE_BYTES],    //in (B_in)                          
                          uint8_t B_out[B_OUT_SIZE_BYTES])  //out (B_out)
{
    sgx_status_t status;
    sgx_status_t retval;

    status = bb_exec(global_eid, &retval, 
                     p_sealed_s, SECRET_KEY_SEALED_SIZE_BYTES, 
                     B_in, B_IN_SIZE_BYTES, 
                     B_out, B_OUT_SIZE_BYTES);

    std::cout << "bb_exec status is " << status << " retval is " << retval << "." << std::endl;                     

    return SGX_SUCCESS;
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    sgx_status_t status;
    
    /*** PROTOCOL(bb--->skg): get_pk_request

    struct get_pk_request {
        char bb_ar_noise[32];
    };    
    ***/

    //TODO- pass bb_ar_noise to skg_initialization

    /*SKG INITIALIZATION*/
    sgx_ec256_public_t* p_skg_pk = NULL;
    sgx_quote_t* p_skg_quote = NULL;
    sgx_sealed_data_t* p_sealed_s_sk = NULL;        

    status = skg_initialization(&p_skg_pk, &p_skg_quote, &p_sealed_s_sk);
    std::cout <<"skg initialization status is " << status << std::endl;
    if(status) return status;
    /*SKG INITIALIZATION end*/

    /*** PROTOCOL(skg--->bb): get_pk_response

    struct get_pk_response {
        char                   skg_ar_noise[32];
        sgx_ec256_public_t     skg_pk;            //pk
        sgx_quote_t            skg_quote;    //Q’
    };
 
    ***/

    //TODO- pass skg_ar_noise to bb_initialization_1

    /*BB INITIALIZATION stage 1*/
    sgx_ec256_public_t* p_bb_pk = NULL;
    uint8_t k_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES];
    memset(k_encrypted, 0, SECRET_KEY_ENCRYPTED_SIZE_BYTES);
    sgx_sealed_data_t* p_sealed_k = NULL;
    sgx_quote_t* p_bb_quote = NULL;

    status = bb_initialization_1(p_skg_pk,p_skg_quote, &p_bb_pk ,&p_sealed_k, &p_bb_quote, k_encrypted);
    std::cout <<"bb initialization 1 status is " << status << std::endl;
    if(status) return status;
    /*BB INITIALIZATION stage 1 end*/

    /*** PROTOCOL(bb--->skg): get_secret_request

    struct get_secret_request {
        sgx_quote_t bb_quote;                        //Q
        sgx_ec256_public_t bb_pk;                    //TODO - should bb_pk be in bb_quote?
        uint8_t k_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES];    //c
    };

    ***/

    /*SKG EXECUTION*/
    uint8_t s_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES];
    memset(s_encrypted, 0, SECRET_KEY_ENCRYPTED_SIZE_BYTES);
    status = skg_execution(p_bb_pk, p_skg_pk, k_encrypted, p_bb_quote, p_sealed_s_sk, s_encrypted);
    std::cout <<"skg execution status is " << status << std::endl;
    if(status) return status;
    /*SKG EXECUTION end*/

    /*** PROTOCOL(skg--->bb): get_secret_response

    struct get_secret_response {
        uint8_t k_encrypted[SECRET_KEY_ENCRYPTED_SIZE_BYTES];    //c
        //TODO - Anti-Replay?
    };

    ***/

    /*BB INITIALIZATION stage 2*/
    sgx_sealed_data_t* p_sealed_s = NULL;    
    status = bb_initialization_2(p_sealed_k, s_encrypted, &p_sealed_s);
    std::cout <<"bb initialization 2 status is " << status << std::endl;
    if(status) return status;
    /*BB INITIALIZATION stage 2 end*/

    /*BB EXECUTION*/
    uint8_t B_out[B_OUT_SIZE_BYTES];
    memset(B_out, 0, B_OUT_SIZE_BYTES);   
    
    uint8_t B_in[B_IN_SIZE_BYTES];          //TODO: Recieve this as input from neighbor
    memset(B_in, 0, B_IN_SIZE_BYTES);

    status = bb_execution(p_sealed_s, B_in, B_out);
    std::cout <<"bb execution status is " << status << std::endl;
    if(status) return status;
    /*BB EXECUTION end*/

    //TODO - write to persistent memory
    free(p_sealed_s);

    free(p_bb_pk);
    free(p_sealed_k);
    free(p_bb_quote);

    free(p_skg_pk);
    free(p_sealed_s_sk);
    free(p_skg_quote);
    return 0;
}
