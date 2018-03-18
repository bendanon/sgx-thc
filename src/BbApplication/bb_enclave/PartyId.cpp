#include "PartyId.h"

PartyId::PartyId(){
    memset(m_id, 0, sizeof(m_id));
}

bool PartyId::FromBuffer(uint8_t** id, size_t* len){
    return serdes(id, len, false);
}

bool PartyId::ToBuffer(uint8_t** id, size_t* len){
    return serdes(id, len, true);
}

PartyId& PartyId::operator=(const PartyId& rhs){
    memcpy(m_id,&rhs,sizeof(m_id));
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
}

bool PartyId::isValid(){
    for(int i = 0; i < sizeof(m_id); i++){
        if(0 != m_id[i]){
            return true;
        }
    }
}

bool PartyId::serdes(uint8_t** id, size_t* len, bool fSer){
    if(*len < PARTY_ID_SIZE_BYTES){
        ocall_print("PartyId::serdes failed, buffer too small, %d", *len);
        return false;
    }
    if(fSer){
        memcpy(*id ,m_id, sizeof(m_id));
    } else {
        memcpy(m_id, *id, sizeof(m_id));
    }               

    *id += PARTY_ID_SIZE_BYTES;
    *len -= PARTY_ID_SIZE_BYTES;

    return true;
}


VertexIterator::VertexIterator() : m_vertices(NULL), m_current(0), m_last(0) { }

bool VertexIterator::GetNext(PartyId& next){
    if(m_vertices == NULL){
        ocall_print("VertexIterator::GetNext - iterator not initialized %d", 0);
        return false;
    }
    if(m_current >= m_last) {                                       
        return false;
    }
    next = m_vertices[m_current++];
    return true;
}

void VertexIterator::SetVertices(PartyId* vertices){ m_vertices = vertices; }
void VertexIterator::SetLast(uint32_t len){ m_last = len; }
