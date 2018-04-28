#include "PartyId.h"

PartyId::PartyId(char c){
    memset(m_id, c, sizeof(m_id));
    memset(m_email, 0, sizeof(m_email));
    memset(m_params, 0, sizeof(m_params));
}

PartyId::PartyId(){
    memset(m_id, 0, sizeof(m_id));
    memset(m_email, 0, sizeof(m_email));
    memset(m_params, 0, sizeof(m_params));
}


bool PartyId::FromBuffer(uint8_t** buffer, size_t* len){
    return serdes(buffer, len, false);
}

bool PartyId::ToBuffer(uint8_t** buffer, size_t* len){
    return serdes(buffer, len, true);
}

PartyId& PartyId::operator=(const PartyId& rhs){
    memcpy(m_id,rhs.m_id,sizeof(m_id));
    memcpy(m_params,rhs.m_params,sizeof(m_params));
    memcpy(m_email,rhs.m_email,sizeof(m_email));
    return *this;
}

bool PartyId::operator< (const PartyId& rhs){
    for(int i = 0; i < sizeof(m_id); i++){

        if(m_id[i] < rhs.m_id[i]){
            return true;
        } else if (m_id[i] > rhs.m_id[i]){
            return false;
        }
    }

    return false;
}

bool PartyId::operator<= (const PartyId& rhs){                
    return *this < rhs || *this == rhs;
}

bool PartyId::operator==(const PartyId& other){
    return 0==memcmp(m_id, other.m_id, PARTY_ID_SIZE_BYTES);
}

bool PartyId::operator!=(const PartyId& other){
    return !(*this == other);
}

void PartyId::Print(){
    print_buffer(m_id, PARTY_ID_SIZE_BYTES);
    print_buffer(m_params, sizeof(m_params));
    ocall_print(m_email);
}

bool PartyId::isValid(){
    for(int i = 0; i < sizeof(m_id); i++){
        if(0 != m_id[i]){
            return true;
        }
    }
}

bool PartyId::AddNeighbor(PartyId* neighbor){
    if(NULL == neighbor){
        ocall_print("PartyId::AddNeighbor - input is NULL");
        return false;
    }
    
    if(MAX_NEIGHBORS(MAX_GRAPH_SIZE) < m_neighbors.size()){
        ocall_print("PartyId::AddNeighbor - The following node has too many (%d) neighbors", m_neighbors.size());
        this->Print();
        return false;
    }

    if(m_neighbors.find(neighbor) != m_neighbors.end()){
        ocall_print("PartyId::AddNeighbor - neighbor is already inserted");
        this->Print();
        return false;
    }

    m_neighbors.insert(neighbor);

    return true;
}

bool PartyId::GetNeighbors(std::queue<PartyId*>& o_queue, std::map<PartyId*,PartyId*>& backtrace){

    for(PartyId* n : m_neighbors) {
        if(backtrace.end() == backtrace.find(n)){
            o_queue.push(n);
            backtrace.insert( std::pair<PartyId*,PartyId*>(n, this) );
        }        
    }

    return true;
}

bool PartyId::Matches(PartyId* other){
    if(*this == *other){
        return false;
    }

    int matchCounter = 0;
    for(int i = 0; i < APP_NUM_OF_PARAMETERS; i++){
        if(m_params[i] == other->m_params[i]){
            matchCounter++;
        }
    }
    return matchCounter == APP_NUM_OF_PARAMETERS;
}

bool PartyId::GetEmail(uint8_t** buffer, size_t* len){
     if(*len < (MAX_EMAIL_SIZE_BYTES)){
        ocall_print("PartyId::serdes failed, buffer too small, %d", *len);
        return false;
    }
    
    size_t printed = snprintf((char*)*buffer, MAX_EMAIL_SIZE_BYTES, "%s", m_email);

    *buffer += printed;
    *len -= printed;

    return true;
}

bool PartyId::serdes(uint8_t** buffer, size_t* len, bool fSer){
    if(*len < (APP_PARTY_FULL_SIZE_BYTES)){
        ocall_print("PartyId::serdes failed, buffer too small, %d", *len);
        return false;
    }
    if(fSer){
        memcpy(*buffer ,m_id, sizeof(m_id));
    } else {
        memcpy(m_id, *buffer, sizeof(m_id));
    }               

    *buffer += sizeof(m_id);
    *len -= sizeof(m_id);

    if(fSer){
        memcpy(*buffer ,(uint8_t*)m_params, sizeof(m_params));

    } else {
        memcpy((uint8_t*)m_params, *buffer, sizeof(m_params));
    }

    *buffer += sizeof(m_params);
    *len -= sizeof(m_params);

    if(fSer){
        memcpy(*buffer ,(uint8_t*)m_email, sizeof(m_email));

    } else {
        memcpy((uint8_t*)m_email, *buffer, sizeof(m_email));
    }

    *buffer += sizeof(m_email);
    *len -= sizeof(m_email);

    return true;
}


VertexIterator::VertexIterator() : m_vertices(NULL), m_current(0), m_last(0) { }

bool VertexIterator::GetNext(PartyId& next){
    if(m_vertices == NULL){
        ocall_print("VertexIterator::GetNext - iterator not initialized %d", 0);
        return false;
    }
    if(0 == m_last){
        return false;
    }
    if(m_current > m_last) {                                       
        return false;
    }
    next = m_vertices[m_current++];
    return true;
}

void VertexIterator::SetVertices(PartyId* vertices){ m_vertices = vertices; }
void VertexIterator::SetLast(uint32_t last){ m_last = last; }
