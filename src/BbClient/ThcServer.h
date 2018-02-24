#ifndef THC_SERVER_H
#define THC_SERVER_H

#include "Queues.h"

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
#include "ReceiverSocket.h"
#include <jsoncpp/json/json.h>

class ThcServer{

public:
    ThcServer(Json::Value& config);
    ~ThcServer();
    void RunServer();
    void SetQueues(Queues* queues);
    

private:
    void startAccept();
    void handleAccept(ReceiverSocket* receiverSocket, const boost::system::error_code& error);

private:
    Queues* m_queues = NULL;
    Json::Value& m_config;
    ReceiverSocket* m_sockets;
    boost::thread** m_threadPtrs;
    uint32_t m_numOfNeighbors;

    boost::asio::io_service m_ioService;
    boost::asio::ip::tcp::acceptor m_acceptor;
    uint32_t m_acceptedConnections;
};

#endif //THC_SERVER_H