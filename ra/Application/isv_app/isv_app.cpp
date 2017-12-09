#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "AttestationClient.h"
#include "VerificationReport.h"
#include "Messages.pb.h"
#include "BbClient.h"
#include "SkgServer.h"

#include "SkgEnclave.h"
#include "BbEnclave.h"

void ocall_print(const char* str) {
    printf("%s\n", str);
}

int Main(int argc, char* argv[]) {
    LogBase::Inst();

    int ret = 0;

    sgx_status_t sgx_ret;
    SkgEnclave* skg_enclave = new SkgEnclave();
    BbEnclave* bb_enclave = new BbEnclave();
    if (SGX_SUCCESS != skg_enclave->createEnclave() || SGX_SUCCESS != bb_enclave->createEnclave()){
        Log("createEnclave failed");
        return -1;
    }

    Messages::PkRequest pkRequest;
    Messages::CertificateMSG skgCertMsg;
    Messages::CertificateMSG bbCertMsg;
    Messages::GetSecretResponse getSecretResponse;

    //TODO: For now, both skg and bb are on the same machine and use the same enclave
    //for testing purposes. In the future, both will encapsulate their own enclaves
    SkgServer skgServer(skg_enclave);
    if(!skgServer.Init())
        Log("SkgServer Failed to Init");

    BbClient bbClient(bb_enclave);
    
    if(!bbClient.hasSecret())
    {
        bbClient.generatePkRequest(pkRequest);

        /*** PROTOCOL(bb--->skg): get_pk_request ***/
        
        skgServer.processPkRequest(pkRequest, skgCertMsg);

        /*** PROTOCOL(skg--->bb): get_pk_response ***/

        bbClient.processPkResponse(skgCertMsg, bbCertMsg);

        /*** PROTOCOL(bb--->skg): get_secret_request ***/

        skgServer.processGetSecretRequest(bbCertMsg, getSecretResponse);

        /*** PROTOCOL(skg--->bb): get_secret_response ***/

        bbClient.processGetSecretResponse(getSecretResponse);
    }

    uint8_t B_out[B_OUT_SIZE_BYTES];
    memset(B_out, 0, B_OUT_SIZE_BYTES);   
    
    uint8_t B_in[B_IN_SIZE_BYTES];          //TODO: Recieve this as input from neighbor
    memset(B_in, 0, B_IN_SIZE_BYTES);

    bbClient.execute(B_in, B_IN_SIZE_BYTES, B_out, B_OUT_SIZE_BYTES);  

    delete bb_enclave;
    delete skg_enclave;
    return ret;
}


int main( int argc, char **argv ) {
    try {
        return Main(argc, argv);
    } catch (std::exception& e) {
        Log("exception: %s", e.what());
    } catch (...) {
        Log("unexpected exception") ;
    }

    return -1;
}







