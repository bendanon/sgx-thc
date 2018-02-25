#ifndef QUEUES_H
#define QUEUES_H

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
#include "../GeneralSettings.h"
#include <boost/unordered_map.hpp>

#include <boost/thread.hpp>
#include <boost/chrono.hpp>
using namespace util;


class Queue{
    
public:
    bool InsertMsg(std::string& msg);
    bool GetMsg(uint32_t roundNumber, std::string& o_msg);
private:
    vector<std::string> m_msg;
    uint32_t m_roundNumber = 0;
};

class Queues{

public:

    bool InsertFromNeighbor(std::string neighborIp, int neighborPort, std::string& msg);

    bool GetMsgFromNeighbor(uint32_t roundNumber, std::string neighborIp, int neighborPort, std::string& msg);
    

private:
    boost::unordered_map<std::string, Queue*> m_map;
    boost::mutex m_mutex;

};

#endif //QUEUES_H