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

class Queues{

    class Queue{
    
    public:

        bool InsertMsg(std::string& msg){

            if(!m_msg.empty()){                
                return false;
            }

            m_msg.push_back(msg);
            m_roundNumber++;

            return true;
        }

        bool GetMsg(uint32_t roundNumber, std::string& o_msg){

            if(roundNumber != m_roundNumber){
                Log("Queue::GetMsg - asked for a message from round %d when holding %d", roundNumber, m_roundNumber);
                return false;
            }

            if(m_msg.empty()){
                return false;
            }

            o_msg = m_msg[0];
            m_msg.clear();

            return true;                        
        }

    private:
        vector<std::string> m_msg;
        uint32_t m_roundNumber = 0;
    };

public:

    bool InsertFromNeighbor(std::string neighborIp, int neighborPort, std::string& msg){

        std::string neighbor = neighborIp + std::to_string (neighborPort);

        bool retval = false;

        m_mutex.lock();

        //If the queue doesn't exist yet, create it        
        if(m_map.find(neighbor) == m_map.end()){
            m_map[neighbor] = new Queue();
        }

        retval = m_map[neighbor]->InsertMsg(msg);

        m_mutex.unlock();

        return retval;
    }

    bool GetMsgFromNeighbor(uint32_t roundNumber, std::string neighborIp, int neighborPort, std::string& msg){

        std::string neighbor = neighborIp + std::to_string (neighborPort);
        
        bool retval = false;
        m_mutex.lock();
        
        if(m_map.find(neighbor) == m_map.end()){
            Log("Queues::GetMsgToNeighbor - neighbor %s does not exist", neighbor);
            return false;
        }

        retval = m_map[neighbor]->GetMsg(roundNumber, msg);

        m_mutex.unlock();

        return retval;
    }
    

private:
    boost::unordered_map<std::string, Queue*> m_map;
    boost::mutex m_mutex;

};

#endif //QUEUES_H