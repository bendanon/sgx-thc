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

void _ocall_print(const char* str) {
    printf("%s\n", str);
}


/*static double current_time()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);

	return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0;
}*/

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */ printf("%s", str);
}

void ocall_current_time(double* time)
{
    if(!time) return;
    //*time = current_time();
    return;
}

void ocall_low_res_time(int* time)
{
    struct timeval tv;
    if(!time) return;
    *time = tv.tv_sec;
    return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

int Main(int argc, char* argv[]) {

    LogBase::Inst();
    
    if(argc != 2){
        Log("Usage: ./app <config_file_name>.json", log::error);
        return -1;
    }

    printf("THC_ENCRYPTED_MSG_SIZE_BYTES for  %d is %lu\n", MAX_GRAPH_SIZE, THC_ENCRYPTED_MSG_SIZE_BYTES);

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

    uint8_t outbuf[THC_ENCRYPTED_MSG_SIZE_BYTES];

    //This shouldn't terminate
    if(!bbClient.runThcProtocol(outbuf, THC_ENCRYPTED_MSG_SIZE_BYTES)){
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







