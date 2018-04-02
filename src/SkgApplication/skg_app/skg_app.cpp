#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "SkgServer.h"
#include "SkgEnclave.h"

void _ocall_print(const char* str) {
    printf("%s\n", str);
}

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

    int ret = 0;

    sgx_status_t sgx_ret;
    SkgEnclave* skg_enclave = new SkgEnclave();
    if (SGX_SUCCESS != skg_enclave->createEnclave()){
        Log("createEnclave failed");
        return -1;
    }

    //TODO: For now, both skg and bb are on the same machine and use the same enclave
    //for testing purposes. In the future, both will encapsulate their own enclaves
    SkgServer skgServer(skg_enclave);
    if(!skgServer.init())
        Log("SkgServer Failed to Init");

    skgServer.start();

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







