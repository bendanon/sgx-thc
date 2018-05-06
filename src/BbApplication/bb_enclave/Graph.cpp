
#include "Edge.h"
#include "PartyId.h"
#include "Graph.h"
//#include "bb_enclave_t.h"

Graph::Graph() : m_verticesLen(0), m_verticesOpenSpot(0), m_edgesOpenSpot(0), m_vertices(NULL){ }

Graph::Graph(uint32_t len) : m_verticesLen(len), m_verticesOpenSpot(0), m_edgesOpenSpot(0){            
    m_vertices = new PartyId[m_verticesLen];
}
Graph::~Graph(){
    delete[] m_vertices;
}

bool Graph::FindClosestMatch(PartyId& source, std::vector<PartyId*>& path){

    std::queue<PartyId*> Q;
    std::map<PartyId*,PartyId*, PartyId::comp> backtrace;

    auto it = m_verticesSet.find(&source);
    if(m_verticesSet.end() == it){
        ocall_print("Graph::FindClosestMatch - failed to find source");
        return false;
    }
    
    PartyId* pSource = *it;

    Q.push(pSource);    

    while(!Q.empty()){
        PartyId* current = Q.front();
        Q.pop();
        
        if(current->Matches(pSource)){

            path.push_back(current);

            while(current != pSource){
                auto next = backtrace.find(current);
                if(backtrace.end() == next){
                    ocall_print("Graph::FindClosestMatch - failed to find backtrace");
                    return false;
                }
                current = next->second;
                path.push_back(current);
            }           

            return true;
        }

        if(!current->GetNeighbors(Q, backtrace)){
            ocall_print("FindShortestPath - failed to get neighbors");
            return false;
        }
    }

    return false;
}

bool Graph::AddEdge(PartyId& idSrc, PartyId& idSink){

    //Add edge only works when the graph is initialized
    if(m_vertices == NULL || m_verticesLen == 0){
        ocall_print("Graph::AddVertex - graph is not initialized");
        return false;
    }

    auto src = m_verticesSet.find(&idSrc);
    if(m_verticesSet.end() == src){
        ocall_print("Graph::AddEdge - idSrc is not contained in m_verticesSet");
        return false;
    }

    auto sink = m_verticesSet.find(&idSink);
    if(m_verticesSet.end() == sink){
        ocall_print("Graph::AddEdge - idDst is not contained in m_verticesSet");
        return false;
    }

    if((*src)->IsNeighborOf(*sink)){
        if(!(*sink)->IsNeighborOf(*src)){
            ocall_print("Graph::AddEdge - src is neighbor of sink but not the other way around...");
            return false;
        }
        return true;
    }

    if(m_edgesOpenSpot >= MAX_EDGES(m_verticesLen)) {
        ocall_print("Graph::AddEdge - graph is full");
        return false;
    }    

    if(!(*src)->AddNeighbor(*sink)){
        ocall_print("Graph::AddEdge - failed to add neighbor");
        return false;
    }

    if(!(*sink)->AddNeighbor(*src)){
        ocall_print("Graph::AddEdge - failed to add neighbor");
        return false;
    }

    m_edgesOpenSpot++;

    return true;
}

bool Graph::AddVertex(PartyId& vertex){

    //Add vertex only works when the graph is initialized
    if(m_vertices == NULL || m_verticesLen == 0){
        ocall_print("Graph::AddVertex - graph is not initialized");
        return false;
    }

    auto search = m_verticesSet.find(&vertex);

    //This means the vertex is already in the graph
    if(m_verticesSet.end() != search) return true; 

    if(m_verticesLen == m_verticesOpenSpot){
        ocall_print("Graph::AddVertex - graph is full");
        return false;
    }
    
    //copy into internal graph memory
    m_vertices[m_verticesOpenSpot] = vertex;

    auto res = m_verticesSet.insert(&m_vertices[m_verticesOpenSpot]);

    if(!res.second){
        ocall_print("Graph::AddVertex - failed to insert vertex");
        return false;
    }

    m_verticesOpenSpot++;

    return true;
}

bool Graph::AddGraph(Graph& other){

    if(!IsInitialized()){
        ocall_print("Graph::AddGraph - graph is not initialized");
        return false;
    }

    //We first add the vertices of the other graph to this graph
    for(PartyId* vertex : other.m_verticesSet){

        if(!this->AddVertex(*vertex)){
            ocall_print("Graph::AddGraph - failed to add vertex");
            return false;
        }
    }

    //Then we add edges
    for(PartyId* vertex : other.m_verticesSet){

         auto src = m_verticesSet.find(vertex);
         if(m_verticesSet.end() == src){
             ocall_print("Graph::AddGraph - failed to find src in graph");
             return false;
         }

        std::queue<PartyId*> neighbors;
        
        if(!vertex->GetNeighbors(neighbors)){
            ocall_print("Graph::AddGraph - failed to get neighbors");
            return false;
        }

        while(!neighbors.empty()){
            auto sink = m_verticesSet.find(neighbors.front());
            if(m_verticesSet.end() == sink){
                ocall_print("Graph::AddGraph - failed to find sink in graph");
                return false;
            }
            if(!this->AddEdge(**src, **sink)){
                ocall_print("Graph::AddGraph - failed to add edge");
                return false;
            }
            neighbors.pop();
        }
        
    }

    return true;
}

uint32_t Graph::IndexOf(PartyId* vertex){

    if(!IsInitialized()){
        ocall_print("Graph::IndexOf - graph is not initialized");
        return false;
    }
    uint32_t position = 0;

    for(PartyId* curr : m_verticesSet){                                        

        if(*curr == *vertex){
            return position;
        }
        position++;
    }

    return MAX_UINT32;
}

bool Graph::Contains(PartyId* src, PartyId* sink){                

    auto it = m_verticesSet.find(src);
    if(m_verticesSet.end() == it){
        ocall_print("Graph::Contains - failed to find source");
        return false;
    }

    if(!(*it)->IsNeighborOf(sink)){
       return false;
    }

    return true;
}

bool Graph::Contains(PartyId* vertex){                
    auto it = m_verticesSet.find(vertex);
    return m_verticesSet.end() != it;
}

uint32_t Graph::GetSize() const {
    return m_verticesOpenSpot;
}

bool Graph::IsInitialized() const {
    return m_vertices != NULL;
}

bool Graph::FromBuffer(uint8_t** buffer, size_t* len) {

    if(IsInitialized()){
        ocall_print("Graph::ToBuffer - called on initialized graph");
        return false;
    }

    if(*len < sizeof(uint32_t)){
        ocall_print("Graph::FromBuffer::m_verticesLen failed, buffer too short, %d", *len);
        return false;
    }
    
    memcpy(&m_verticesLen, *buffer, sizeof(uint32_t));
    *buffer += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    if(m_verticesLen > MAX_GRAPH_SIZE){
        ocall_print("Graph::FromBuffer - bad value for m_verticesLen %d", m_verticesLen);
        return false;
    }

    m_vertices = new PartyId[m_verticesLen];

    //Read m_verticesLen vertices from buffer
    for(int i = 0; i < m_verticesLen; i++) {
        PartyId vertex;

        if(!vertex.FromBuffer(buffer, len)){ //TODO - need to add the vertex to other data structures
            ocall_print("Graph::FromBuffer - failed to get all graph elements");
            return false;
        }

        if(!this->AddVertex(vertex)){
            ocall_print("Graph::FromBuffer - failed to add vertex");
            return false;
        }
    }

    //Sanity
    if(m_verticesOpenSpot != m_verticesLen){
        ocall_print("Graph::FromBuffer - m_verticesOpenSpot != m_verticesLen");
        return false;
    }

    if(*len < sizeof(uint32_t)){
        ocall_print("Graph::FromBuffer- failed, buffer too short, %d", *len);
        return false;
    }
    
    uint32_t edgesLen;

    memcpy(&edgesLen, *buffer, sizeof(uint32_t));
    *buffer += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    #ifndef SCHIZZO_TEST
    if(edgesLen > MAX_EDGES(m_verticesLen)){
        ocall_print("Graph::FromBuffer - bad value for edgesLen %d", edgesLen);
        return false;
    }
    #endif    
    
    //Read edgesLen PartyIds from buffer
    for(int i = 0; i < edgesLen; i++) {
        Edge edge;

        if(!edge.FromBuffer(buffer, len)){
            ocall_print("Graph::FromBuffer - failed to get all graph elements");
            return false;
        }

        if((edge.GetSrc() >= m_verticesOpenSpot) || (edge.GetSink() >= m_verticesOpenSpot)){
            ocall_print("Graph::FromBuffer - src or edge are out of range");
            return false;
        }

        //Here I use the fact that the graph arrives sorted
        if(!this->AddEdge(m_vertices[edge.GetSrc()], m_vertices[edge.GetSink()])){
            ocall_print("Graph::FromBuffer - failed to add edge");
            return false;
        }        
    }
    //Sanity
    if(m_edgesOpenSpot != edgesLen){
        ocall_print("Graph::FromBuffer - m_edgesOpenSpot != edgesLen");
        return false;
    }

    return true;
}


bool Graph::verticesToBuffer(std::map<PartyId*, int, PartyId::comp>& order, uint8_t** buffer, size_t* len){
    if(!IsInitialized()){
        ocall_print("Graph::verticesToBuffer - called on not initialized graph");
        return false;
    }

    if(*len < sizeof(uint32_t)){
        ocall_print("Graph::verticesToBuffer - m_verticesOpenSpot failed, buffer too short, %d", *len);
        return false;
    }
    
    memcpy(*buffer, &m_verticesOpenSpot, sizeof(uint32_t));
    *buffer += sizeof(m_verticesOpenSpot);
    *len -= sizeof(m_verticesOpenSpot);

    if(*len < m_verticesOpenSpot*APP_PARTY_FULL_SIZE_BYTES){
        ocall_print("Graph::verticesToBuffer - m_vertices failed, buffer too short, %d", *len);
        return false;
    }

    int position = 0;

    //Write m_verticesOpenSpot vertices from buffer
    for(PartyId* vertex : m_verticesSet){
        if(!vertex->ToBuffer(buffer, len)){
            ocall_print("Graph::verticesToBuffer - failed to serialize vertex");
            return false;
        }

        //TODO - validate insertion everywhere else...
        auto it = order.insert( std::pair<PartyId*, int>(vertex, position++) );
        if(!it.second){
            ocall_print("Graph::verticesToBuffer - failed to insert pair");
            return false;
        }
    }

    return true;
}

bool Graph::edgesToBuffer(std::map<PartyId*, int, PartyId::comp>& order, uint8_t** buffer, size_t* len){
    if(!IsInitialized()){
        ocall_print("Graph::edgesToBuffer - called on not initialized graph");
        return false;
    }

    if(*len < sizeof(uint32_t)){
        ocall_print("Graph::edgesToBuffer - m_edgesOpenSpot failed, buffer too short, %d", *len);
        return false;
    }
    
    memcpy(*buffer, &m_edgesOpenSpot, sizeof(uint32_t));
    *buffer += sizeof(m_edgesOpenSpot);
    *len -= sizeof(m_edgesOpenSpot);

    if(*len < m_edgesOpenSpot*EDGE_SIZE_BYTES){
        ocall_print("Graph::edgesToBuffer - m_edges failed, buffer too short, %d", *len);
        return false;
    }

    //TODO - define a comparison function for edges
    std::set<Edge> inserted;

    //Write all edges to buffer as indices
    for(PartyId* vertex : m_verticesSet){
        
        std::queue<PartyId*> neighbors;
        if(!vertex->GetNeighbors(neighbors)){
            ocall_print("Graph::edgesToBuffer - failed to get neighbors");
            return false;
        }

        Edge edge;
        auto srcIdx = order.find(vertex);

        if(order.end() == srcIdx){
            ocall_print("Graph::edgesToBuffer - failed to get index of src");
            return false;
        }

        edge.SetSrc(srcIdx->second);

        while(!neighbors.empty()){

            auto sinkIdx = order.find(neighbors.front());
            if(order.end() == sinkIdx){
                ocall_print("Graph::edgesToBuffer - failed to get index of sink");
                return false;
            }

            edge.SetSink(sinkIdx->second);

            //Serialize without duplicates
            auto it = inserted.insert(edge);
            if(it.second){

                if(!edge.ToBuffer(buffer, len)){
                    ocall_print("Graph::edgesToBuffer - failed to serialize edge");
                    return false;
                }
            }

            neighbors.pop();
        }
    }

    //TODO - make sure m_edgesOpenSpot is maintained properly
    if(inserted.size() != m_edgesOpenSpot){
        ocall_print("Graph::edgesToBuffer - inserted more edges than expected");
        return false;
    }
    
    return true;
}


bool Graph::ToBuffer(uint8_t** buffer, size_t* len) {

    if(!IsInitialized()){
        ocall_print("Graph::ToBuffer - called on not initialized graph");
        return false;
    }

    std::map<PartyId*, int, PartyId::comp> order;

    if(!this->verticesToBuffer(order, buffer, len)){
        ocall_print("Graph::ToBuffer - verticesToBuffer failed");
        return false;
    }

    if(!this->edgesToBuffer(order, buffer, len)){
        ocall_print("Graph::ToBuffer - edgesToBuffer failed");
        return false;
    }    

    return true;
}

void Graph::Print(){
    ocall_print("m_verticesLen: %d", m_verticesLen);
    ocall_print("m_verticesOpenSpot: %d", m_verticesOpenSpot);
    ocall_print("m_edgesOpenSpot: %d", m_edgesOpenSpot);

    for(PartyId* vertex : m_verticesSet){
        ocall_print("===============VERTEX=======================");
        vertex->Print();
        ocall_print("===============EDGES========================");
        std::queue<PartyId*> neighbors;
        if(!vertex->GetNeighbors(neighbors)){
            ocall_print("Graph::Print - failed to get neighbors");
            return;
        }
        while(!neighbors.empty()){
            neighbors.front()->Print();
            neighbors.pop();
        }
        ocall_print("");
    }
}

bool Graph::IsEquivalent(Graph* p_other){
    return this->Contains(p_other) && p_other->Contains(this);
}

bool Graph::Contains(Graph* p_other){
    
    for(PartyId* vertex : m_verticesSet){

        if(!p_other->Contains(vertex)){
            ocall_print("Graph::Contains - other does not contain vertex");
            vertex->Print();
            return false;
        }

        std::queue<PartyId*> neighbors;
        if(!vertex->GetNeighbors(neighbors)){
            ocall_print("Graph::Contains - failed to get neighbors");
            return false;
        }

        while(!neighbors.empty()){

            if(!p_other->Contains(vertex, neighbors.front())){
                ocall_print("Graph::Contains - other does not contain edge");
                return false;
            }
            neighbors.pop();
        }        
    }

    return true; 
}

//TODO: Calculate actual diameter
uint32_t Graph::GetDiameter(){
    return m_verticesLen;
}