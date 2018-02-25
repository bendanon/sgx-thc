#ifndef CLIENTSOCKET_H
#define CLIENTSOCKET_H

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
#include "Messages.pb.h"
#include "Network_def.h"
#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include "../GeneralSettings.h"

using namespace util;

class SenderSocket{

public:
    SenderSocket();
    ~SenderSocket();
    bool Init(std::string ip, int port, int localPort);
    bool Send(uint8_t* buffer, size_t bufferLen);

private:
    bool serializeBbMessage(uint8_t* inbuf, size_t inbuf_size, vector<std::string>& o_msg);
    void close();
private:
    boost::asio::io_service m_ioService;
    boost::asio::ip::tcp::socket m_socket;
    uint32_t m_localPort;
};

#endif