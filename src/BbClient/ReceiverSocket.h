#ifndef RECEIVER_SOCKET_H
#define RECEIVER_SOCKET_H

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
#include <boost/lexical_cast.hpp>
#include "Messages.pb.h"
#include "Network_def.h"


class ReceiverSocket{

public:
    
    ReceiverSocket();
    ~ReceiverSocket();
    bool Init(Queues* p_queues, size_t numOfVertices);
    void Receive();
    boost::asio::ip::tcp::socket& socket();
    
private:
    void close();
    bool read(uint32_t& port, std::string& msg);

private:
    boost::asio::io_service m_ioService;
    boost::asio::ip::tcp::socket m_socket;
    Queues* m_queues = NULL;

    uint8_t* m_encrypted;
    size_t m_encryptedSize;
    
    //For identification
    std::string m_peerIp; 
    uint32_t m_peerPort;
};

#endif //RECEIVER_SOCKET_H