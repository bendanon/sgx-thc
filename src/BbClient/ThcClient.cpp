#include "ThcClient.h"

ThcClient::ThcClient(Json::Value& config, BbEnclave* pEnclave): m_config(config), m_pEnclave(pEnclave) {

    const Json::Value& neighConfig = m_config["neighbors"];

    m_numOfNeighbors = neighConfig.size();

    m_sockets = new SenderSocket[m_numOfNeighbors];
}

ThcClient::~ThcClient(){
    delete[] m_sockets;
}

bool ThcClient::Init(){

    uint8_t firstMsgBuf[THC_ENCRYPTED_MSG_SIZE_BYTES];

    if(SGX_SUCCESS != m_pEnclave->GenerateFirstMessage(firstMsgBuf, THC_ENCRYPTED_MSG_SIZE_BYTES)){
        Log("ThcClient::Init - failed to generate first message", log::error);
        return false;
    }    

    const Json::Value& neighConfig = m_config["neighbors"];

    for(int i = 0; i < m_numOfNeighbors; i++){

        std::string ip = neighConfig[i]["ip"].asString();
        uint32_t port = neighConfig[i]["port"].asUInt();

        if(!m_sockets[i].Init(ip, port, m_config["port"].asUInt())){
            Log("ThcClient::Init - failed to prepare socket for %s, %d", ip, port, log::error);
            return false;
        }
        else
        {
            Log("ThcClient::Init - SenderSocket init succesfully to %d!!", i);
        }

        if(!m_sockets[i].Send(firstMsgBuf, THC_ENCRYPTED_MSG_SIZE_BYTES)){
            Log("ThcClient::Init - failed to send first msg to %s, %d", ip, port, log::error);
            return false;
        }
        else
        {
            Log("ThcClient::Init - first message sent succesfully to %d!!", i);
        }
    }

    return true;
}


bool ThcClient::Run(Queues* p_queues, uint8_t* outbuf, size_t outbuf_len){

    const Json::Value& neighConfig = m_config["neighbors"];

    for(int roundNumber = 1; true; roundNumber++){        

        for(int neighborIndex = 0; neighborIndex < m_numOfNeighbors; neighborIndex++){
            
            std::string ip = neighConfig[neighborIndex]["ip"].asString();
            uint32_t port = neighConfig[neighborIndex]["port"].asUInt();
            std::string msg;
            uint32_t numOfTries = 0;

            while(!p_queues->GetMsgFromNeighbor(roundNumber, ip, port, msg) && ++numOfTries <= THC_MAX_NUM_OF_TRIES)
            {
                //Log("ThcClient::Run - GetMsgFromNeighbor failed. retrying...");
                boost::this_thread::sleep_for(boost::chrono::seconds{THC_SLEEP_BETWEEN_RETRIES_SECONDS});
            }

            if(numOfTries <= THC_MAX_NUM_OF_TRIES){

                if(!execute((uint8_t*)msg.c_str(), THC_ENCRYPTED_MSG_SIZE_BYTES, outbuf, outbuf_len)){
                    Log("ThcClient::Run - failed to execute", log::error);
                    return false;
                }

                if(thcFinished(outbuf, outbuf_len)){
                    return true;
                }
            }
            else{

                Log("ThcClient::Run - aborting...");
                if(!execute(NULL, 0, NULL, 0)){
                    Log("ThcClient::Run - failed to execute abort", log::error);
                    return false;
                }
            }
        }

        for(int neighborIndex = 0; neighborIndex < m_numOfNeighbors; neighborIndex++){

            if(!m_sockets[neighborIndex].Send(outbuf, outbuf_len)){

                std::string ip = neighConfig[neighborIndex]["ip"].asString();
                uint32_t port = neighConfig[neighborIndex]["port"].asUInt();
                Log("ThcClient::Run - failed to send message to neighbor %s, %d", ip, port, log::error);
                return false;
            }
            /*else{
                std::string ip = neighConfig[neighborIndex]["ip"].asString();
                uint32_t port = neighConfig[neighborIndex]["port"].asUInt();
                Log("ThcClient::Run - %d message successfully sent to %s, %d+++++", roundNumber, ip, port);
            }*/
        }       

    }
}

bool ThcClient::thcFinished(uint8_t* outbuf, size_t outbuf_len){
    if(0==memcmp(ABORT_MESSAGE, outbuf, sizeof(ABORT_MESSAGE))){
        Log("BbClient::handleBbMsg - abort");
        return true;               
    }

    if(0==memcmp(DEBUG_RESULT_MESSAGE, outbuf, sizeof(DEBUG_RESULT_MESSAGE))){
        Log("BbClient::handleBbMsg - result");        
        return true;               
    }

    return false;
}

bool ThcClient::execute(uint8_t* B_in, size_t B_in_size, 
                        uint8_t* B_out, size_t B_out_size) {


    sgx_status_t status;    

    status = m_pEnclave->bbExec(B_in, B_in_size, B_out, B_out_size);

    if(status)
    {
        Log("bbExec failed with status is %d", status);
        return false;
    }

    Log("ThcClient::execute - success");
    return true;
}