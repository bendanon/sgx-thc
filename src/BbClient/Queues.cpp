
#include "Queues.h"

bool Queue::InsertMsg(std::string& msg){

    if(!m_msg.empty()){                
        return false;
    }

    m_msg = msg;
    m_roundNumber++;

    return true;
}

bool Queue::GetMsg(uint32_t roundNumber, std::string& o_msg){

    if(roundNumber != m_roundNumber){
        //Log("Queue::GetMsg - asked for a message from round %d when holding %d", roundNumber, m_roundNumber);
        return false;
    }

    if(m_msg.empty()){
        return false;
    }

    o_msg = m_msg;
    m_msg = "";

    return true;                        
}


bool Queues::InsertFromNeighbor(std::string neighborIp, int neighborPort, std::string& msg){

    std::string neighbor = neighborIp + std::to_string (neighborPort);
    //Log("Queues::InsertFromNeighbor - inserting from %s", neighbor);

    bool retval = true;

    m_mutex.lock();

    //If the queue doesn't exist yet, create it        
    if(m_map.find(neighbor) == m_map.end()){
        m_map[neighbor] = new Queue();
    }

    retval = m_map[neighbor]->InsertMsg(msg);

    m_mutex.unlock();

    return retval;
}

bool Queues::GetMsgFromNeighbor(uint32_t roundNumber, std::string neighborIp, int neighborPort, std::string& msg){

    std::string neighbor = neighborIp + std::to_string (neighborPort);
    //Log("Queues::GetMsgFromNeighbor - getting from %s for round %d", neighbor, roundNumber);
    
    bool retval = false;
    m_mutex.lock();
    
    if(m_map.find(neighbor) == m_map.end()){
        //Log("Queues::GetMsgFromNeighbor - neighbor %s does not exist", neighbor);
        retval = false;
    }
    else {
        retval = m_map[neighbor]->GetMsg(roundNumber, msg);
    }    

    m_mutex.unlock();

    /*
    if(retval){
        Log("Queues::GetMsgFromNeighbor - getting from %s for round %d succeeded. Length is %d", neighbor, roundNumber, msg.length());
    } else{
        Log("Queues::GetMsgFromNeighbor - getting from %s for round %d failed", neighbor, roundNumber);

    }
    */

    return retval;
}