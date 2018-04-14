#include "PartyId.h"

PartyId::PartyId(){
    memset(m_id, 0, sizeof(m_id));
}

bool PartyId::FromBuffer(uint8_t** buffer, size_t* len){
    return serdes(buffer, len, false);
}

bool PartyId::ToBuffer(uint8_t** buffer, size_t* len){
    return serdes(buffer, len, true);
}

PartyId& PartyId::operator=(const PartyId& rhs){
    memcpy(m_id,rhs.m_id,sizeof(m_id));
    memcpy(m_auxData,rhs.m_auxData,sizeof(m_auxData));
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
    print_buffer(m_auxData, sizeof(m_auxData));
}

bool PartyId::isValid(){
    for(int i = 0; i < sizeof(m_id); i++){
        if(0 != m_id[i]){
            return true;
        }
    }
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

    *buffer += PARTY_ID_SIZE_BYTES;
    *len -= PARTY_ID_SIZE_BYTES;

    if(fSer){
        memcpy(*buffer ,(uint8_t*)m_auxData, sizeof(m_auxData));

    } else {
        memcpy((uint8_t*)m_auxData, *buffer, sizeof(m_auxData));
    }

    *buffer += APP_PARTY_AUX_SIZE_BYTES;
    *len -= APP_PARTY_AUX_SIZE_BYTES;

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
