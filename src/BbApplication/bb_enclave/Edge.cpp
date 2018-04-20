#include "Edge.h"


Edge::Edge(): m_idxSrc(MAX_UINT32), m_idxSink(MAX_UINT32) { }
Edge::Edge(uint32_t idxSrc, uint32_t idxSink) : m_idxSrc(idxSrc), m_idxSink(idxSink) { }
void Edge::SetSrc(uint32_t idxSrc) { m_idxSrc = idxSrc; }
void Edge::SetSink(uint32_t idxSink) { m_idxSink = idxSink; }
bool Edge::IsValid() { return (MAX_UINT32 != m_idxSrc) && (MAX_UINT32 != m_idxSink); }
uint32_t Edge::GetSrc() const { return m_idxSrc; }
uint32_t Edge::GetSink() const { return m_idxSink; }

//This means the graph is undirected
bool Edge::operator==(const Edge& other){
    return (m_idxSrc == other.m_idxSrc && m_idxSink == other.m_idxSink) ||
            (m_idxSrc == other.m_idxSink && m_idxSink == other.m_idxSrc);
}

Edge& Edge::operator=(const Edge& rhs){
    m_idxSrc = rhs.m_idxSrc;
    m_idxSink = rhs.m_idxSink;
    return *this;
}

bool Edge::FromBuffer(uint8_t** buf, size_t* len){
    if(*len < EDGE_SIZE_BYTES){
        ocall_print("Edge::FromBuffer - failed, buffer too small, %d", *len);
        return false;
    }

    memcpy(&m_idxSrc, *buf, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    memcpy(&m_idxSink, *buf, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
    *len -= sizeof(uint32_t);
    
    return true;
}

bool Edge::ToBuffer(uint8_t** buf, size_t* len){
    if(*len < EDGE_SIZE_BYTES){
        ocall_print("Edge::ToBuffer - failed, buffer too small, %d", *len);
        return false;
    }

    memcpy(*buf, &m_idxSrc, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    memcpy(*buf, &m_idxSink, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
    *len -= sizeof(uint32_t);
    
    return true;
}

void Edge::Print(){
    char buf[EDGE_PRINT_SIZE_BYTES];
    snprintf(buf,EDGE_PRINT_SIZE_BYTES,"[%d,%d]", m_idxSrc, m_idxSink);
    ocall_print(buf);
}

EdgeIterator::EdgeIterator() : m_edges(NULL), m_current(0), m_last(0) { }

bool EdgeIterator::GetNext(Edge& next){
    if(m_edges == NULL){
        ocall_print("EdgeIterator::GetNext - iterator not initialized");
        return false;
    }
    if(0 == m_last){
        return false;
    }
    if(m_current > m_last) {                                       
        return false;
    }
    next = m_edges[m_current++];
    return true;
}

void EdgeIterator::SetEdges(Edge* edges){ m_edges = edges; }
void EdgeIterator::SetLast(uint32_t last){ m_last = last; }