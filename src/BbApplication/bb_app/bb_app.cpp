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

#include <string>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;

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
    
    if(argc != 3){
        Log("Usage: ./app <config_file_name>.json <output_file_name>.json", log::error);
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

    size_t graphSize = config["num_of_nodes"].asUInt();

    if(MAX_GRAPH_SIZE < graphSize){
        Log("Graph size %d is bigger than maximum %d", graphSize, MAX_GRAPH_SIZE);
        return -1;
    }

    size_t outbufSize = THC_ENCRYPTED_MSG_SIZE_BYTES(graphSize);
    Log("graphSize is %d, THC_ENCRYPTED_MSG_SIZE_BYTES(graphSize) is %d", graphSize, outbufSize);
    uint8_t* outbuf = new uint8_t[outbufSize];

    //This shouldn't terminate
    if(!bbClient.runThcProtocol(outbuf, outbufSize)){
        Log("Failed obtain result");
        ret = -1;
    }

    
    Json::Value main, path;   
       
    string text((char*)outbuf, outbufSize);

    char_separator<char> sep(", ");
    tokenizer<char_separator<char>> tokens(text, sep);
    int position = 0;
    
    for (const auto& t : tokens) {
        if (!boost::starts_with(t, "RESULT") && t.find("@") != std::string::npos){
            path[position++]["email"] = t;
            cout << t << "." << endl;
        }
    }

    main["match"] = path[0]["email"];
    main["path"] = path;

    std::ofstream ofs (argv[2], std::ofstream::out);
    ofs << main.toStyledString();
    ofs.close();    

    delete outbuf;
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







