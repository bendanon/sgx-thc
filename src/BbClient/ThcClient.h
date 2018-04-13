#ifndef THC_CLIENT_H
#define THC_CLIENT_H

#include "Queues.h"
#include "SenderSocket.h"

#include "LogBase.h"

#include <vector>
#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <functional>
#include <boost/asio/buffer.hpp>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <jsoncpp/json/json.h>
#include "BbEnclave.h"

class ThcClient{
public:
    ThcClient(Json::Value& config, BbEnclave* pEnclave);
    ~ThcClient();

    bool Run(Queues* p_queues, uint8_t* outbuf, size_t outbuf_len);
    bool Init();

private:
    bool serializeBbMessage(uint8_t* inbuf, size_t inbuf_size, vector<std::string>& o_msg);

    /*
    [Execution: input sealed data (s), memory buffer B_in]
    1. Unseal s
    2. Execute B_out=X_s(B_in)
    3. Output B_out
    */
    bool execute(uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size);

    bool thcFinished(uint8_t* outbuf, size_t outbuf_len);

private:
    Json::Value& m_config;
    BbEnclave* m_pEnclave;

    SenderSocket* m_sockets;
    uint32_t m_numOfNeighbors;

    uint8_t* m_encrypted;
    size_t m_encryptedSize;

    bool* m_abortedSockets;
    uint32_t m_timesSlept = 0;
};

#endif //THC_CLIENT_H