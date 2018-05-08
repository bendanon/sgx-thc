#include "ThcClient.h"

ThcClient::ThcClient(Json::Value& config, BbEnclave* pEnclave): m_config(config), 
                                                                m_pEnclave(pEnclave),
                                                                m_sockets(NULL),
                                                                m_abortedSockets(NULL),
                                                                m_encrypted(NULL),
                                                                m_encryptedSize(0) { }

ThcClient::~ThcClient(){
    delete[] m_sockets;
    delete m_abortedSockets;
    delete m_encrypted;
}

bool ThcClient::Init(){

    m_numOfNeighbors = m_config["neighbors"].size();
    if(0 == m_numOfNeighbors){
        Log("ThcClient::Init - invalid num of neighbors", log::error);
        return false;
    }

    m_sockets = new SenderSocket[m_numOfNeighbors];
    if(NULL == m_sockets){
        Log("ThcClient::Init - failed to allocate SenderSockets array", log::error);
        return false;
    }

    m_abortedSockets = new bool[m_numOfNeighbors];
    if(NULL == m_abortedSockets){
        Log("ThcClient::Init - failed to allocate aborted sockets array", log::error);
        return false;
    }

    size_t numOfNodes = m_config["num_of_nodes"].asUInt();        
    if(0 == numOfNodes){
        Log("ThcClient::Init - invalid num of nodes", log::error);
        return false;
    }

    m_encryptedSize = THC_ENCRYPTED_MSG_SIZE_BYTES(numOfNodes);

    m_encrypted = new uint8_t[m_encryptedSize];
    if(NULL == m_encrypted){
        Log("ThcClient::Init - failed to encrypted buffer", log::error);
        return false;
    }    

    if(SGX_SUCCESS != m_pEnclave->GenerateFirstMessage(m_encrypted, m_encryptedSize)){
        Log("ThcClient::Init - failed to generate first message", log::error);
        return false;
    }    

    const Json::Value& neighConfig = m_config["neighbors"];

    for(int i = 0; i < m_numOfNeighbors; i++){

        std::string ip = neighConfig[i]["ip"].asString();
        uint32_t port = neighConfig[i]["port"].asUInt();

        //Initialization
        m_abortedSockets[i] = false;

        if(!m_sockets[i].Init(ip, port, m_config["port"].asUInt())){
            Log("ThcClient::Init - failed to prepare socket for %s, %d", ip, port, log::error);
            m_abortedSockets[i] = true;
            //return false;
        }
        else
        {
            //Log("ThcClient::Init - SenderSocket init succesfully to %d!!", i);
        }

        if(!m_sockets[i].Send(m_encrypted, m_encryptedSize)){
            Log("ThcClient::Init - failed to send first msg to %s, %d", ip, port, log::error);
            //return false;
            m_abortedSockets[i] = true;
        }
        else
        {
            //Log("ThcClient::Init - first message sent succesfully to %d!!", i);
        }
    }

    return true;
}


bool ThcClient::Run(Queues* p_queues, uint8_t* outbuf, size_t outbuf_len){


    if(m_encryptedSize != outbuf_len){
        Log("ThcClient::Run - m_encryptedSize(%d) != outbuf_len(%d)", m_encryptedSize, outbuf_len);
        return false;
    }

    const Json::Value& neighConfig = m_config["neighbors"];

    for(int roundNumber = 1; true; roundNumber++){        

        for(int neighborIndex = 0; neighborIndex < m_numOfNeighbors; neighborIndex++){
            
            
            std::string ip = neighConfig[neighborIndex]["ip"].asString();
            uint32_t port = neighConfig[neighborIndex]["port"].asUInt();
            std::string msg;

            //If this neighbor is aborted, don't recieve message from it. 
            //just send another abort to the black box

            while(!m_abortedSockets[neighborIndex] && 
                  !p_queues->GetMsgFromNeighbor(roundNumber, ip, port, msg))
            {
                 boost::this_thread::sleep_for(boost::chrono::milliseconds{1});
                 m_timesSlept++;
            }

            if(m_abortedSockets[neighborIndex]){

                Log("ThcClient::Run - aborting...");
                if(!execute(NULL, 0, outbuf, outbuf_len)){
                    Log("ThcClient::Run - failed to execute abort", log::error);
                    return false;
                }
                m_abortedSockets[neighborIndex] = true;

            } else if(m_encryptedSize ==  msg.length()) {

                if(!execute((uint8_t*)msg.c_str(), m_encryptedSize, outbuf, outbuf_len)){
                    Log("ThcClient::Run - failed to execute", log::error);
                    abort();
                    return false;
                }
            } else{
                abort();
            }            

            if(thcFinished(outbuf, outbuf_len)){
                Log("ThcClient::Run - Times slept: %d", m_timesSlept);
                return true;
            }
        }

        

        for(int neighborIndex = 0; neighborIndex < m_numOfNeighbors; neighborIndex++){

            //If the neighbor is aborted, we dont send messages to it
            if(m_abortedSockets[neighborIndex]) continue;

            if(!m_sockets[neighborIndex].Send(outbuf, outbuf_len)){

                std::string ip = neighConfig[neighborIndex]["ip"].asString();
                uint32_t port = neighConfig[neighborIndex]["port"].asUInt();
                Log("ThcClient::Run - failed to send message to neighbor %s, %d", ip, port, log::error);
                //return false;
                m_abortedSockets[neighborIndex] = true;
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
        Log("BbClient::thcFinished %d got abort", m_config["port"].asUInt());
        return true;               
    }

    if(0==memcmp(RESULT_CANARY NO_MATCH_STRING, outbuf, strlen(RESULT_CANARY NO_MATCH_STRING))){
        Log("BbClient::thcFinished %d no match", m_config["port"].asUInt());        
        return true;               
    }

    if(0==memcmp(RESULT_CANARY, outbuf, strlen(RESULT_CANARY))){
        Log("BbClient::thcFinished %d, result is %s", m_config["port"].asUInt(), (char*)outbuf);        
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

    //Log("ThcClient::execute - success");
    return true;
}