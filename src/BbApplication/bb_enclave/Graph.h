#include "PartyId.h"
#include "Edge.h"
#include <queue>
#include <vector>

#ifndef GRAPH_H
#define GRAPH_H

class Graph {        

    public: 
        
        Graph();

        Graph(uint32_t len);

        ~Graph();

        bool AddEdge(PartyId& idSrc, PartyId& idSink);

        bool AddVertex(PartyId& id);

        bool AddGraph(Graph& other);

        uint32_t IndexOf(PartyId* vertex);

        bool Contains(PartyId* idSrc, PartyId* idSink);

        bool Contains(PartyId* vertex);

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

        bool verticesToBuffer(std::map<PartyId*, int, PartyId::comp>& order, uint8_t** buffer, size_t* len);

        bool edgesToBuffer(std::map<PartyId*, int, PartyId::comp>& order, uint8_t** buffer, size_t* len);

    private:
        uint32_t m_verticesLen;
        uint32_t m_verticesOpenSpot;
        PartyId* m_vertices;
        std::set<PartyId::ptr, PartyId::comp> m_verticesSet; //TODO - attach copmarison class

        uint32_t m_edgesOpenSpot;
};

#endif //GRAPH_H