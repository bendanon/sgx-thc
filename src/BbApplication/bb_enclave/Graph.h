#include "PartyId.h"
#include "Edge.h"
#include <queue>
#include <vector>
#include <map>

#ifndef GRAPH_H
#define GRAPH_H

class Graph {        

    public: 
        
        Graph();

        Graph(uint32_t len);

        ~Graph();

        bool AddEdge(PartyId& idSrc, PartyId& idSink);
        bool VertexAt(uint32_t idx, PartyId& pid);

        //Inserts id in its ordered position position, keeping the list sorted
        bool AddVertex(PartyId& id);

        bool GetVertexIterator(VertexIterator& iter);

        bool GetEdgeIterator(EdgeIterator& iter);

        uint32_t IndexOf(PartyId& pid);

        uint32_t IndexOf(Edge& edge);

        bool Contains(Edge& e);

        bool Contains(PartyId& pid);

        bool Contains(Graph* p_other);

        uint32_t GetSize() const;

        bool IsInitialized() const;

        bool FromBuffer(uint8_t** buffer, size_t* len);

        bool ToBuffer(uint8_t** buffer, size_t* len);

        void Print();

        bool IsEquivalent(Graph* p_other);        

        uint32_t GetDiameter();

        bool FindClosestMatch(PartyId& source, std::vector<PartyId*>& path);

    private:
        PartyId* getVertexPtr(PartyId& id);

    private:
        uint32_t m_verticesLen;
        uint32_t m_verticesOpenSpot;
        PartyId* m_vertices;
        Edge* m_edges;
        uint32_t m_edgesLen;
        uint32_t m_edgesOpenSpot;
        std::priority_queue<PartyId*> m_q;
};

#endif //GRAPH_H