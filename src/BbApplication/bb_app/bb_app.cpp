#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "AttestationClient.h"
#include "VerificationReport.h"
#include "Messages.pb.h"
#include "BbClient.h"
#include "BbEnclave.h"

#include <fstream>
#include <jsoncpp/json/json.h> // or jsoncpp/json.h , or json/json.h etc.

void ocall_print(const char* str) {
    printf("%s\n", str);
}

int Main(int argc, char* argv[]) {

    LogBase::Inst();

    if(argc != 2){
        Log("Usage: ./app <config_file_name>.json", log::error);
        return -1;
    }
    
    ifstream ifs(argv[1]);
    Json::Reader reader;
    Json::Value config;
    reader.parse(ifs, config); // reader can also read strings    

    int ret = 0;

    sgx_status_t sgx_ret;
    BbEnclave* bb_enclave = new BbEnclave();
    if (SGX_SUCCESS != bb_enclave->createEnclave()) {
        Log("createEnclave failed");
        return -1;
    }

    BbClient bbClient(bb_enclave, config);

    while(!bbClient.hasSecret()) {
        bbClient.obtainSecretFromSkg();        
    }

    //This shouldn't terminate
    if(!bbClient.runThcProtocol()){
        Log("Failed obtain result");
        ret = -1;
    }

    delete bb_enclave;
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







