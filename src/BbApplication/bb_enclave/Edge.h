#include "../GeneralSettings.h"
#include "../common_enclave/common_enclave.h"
#include "bb_enclave_t.h"
#ifndef EDGE_H
#define EDGE_H

class Edge {

    public:
        Edge();
        Edge(uint32_t idxSrc, uint32_t idxSink);
        void SetSrc(uint32_t idxSrc);
        void SetSink(uint32_t idxSink);
        bool IsValid();
        uint32_t GetSrc() const;
        uint32_t GetSink() const;

        //This means the graph is undirected
        bool operator==(const Edge& other);

        Edge& operator=(const Edge& rhs);

        bool FromBuffer(uint8_t** buf, size_t* len);

        bool ToBuffer(uint8_t** buf, size_t* len);

        void Print();

    private:
        uint32_t m_idxSrc;
        uint32_t m_idxSink;
};

class EdgeIterator
{
    public:
        EdgeIterator();

        bool GetNext(Edge& next);

        void SetEdges(Edge* edges);
        void SetLast(uint32_t len);

    private:
        Edge* m_edges;
        uint32_t m_current;
        uint32_t m_last;        
};

#endif //EDGE_H