
#include "Edge.h"
#include "PartyId.h"
#include "Graph.h"
//#include "bb_enclave_t.h"

Graph::Graph() : m_verticesLen(0), m_edgesLen(0), m_verticesOpenSpot(0), m_edgesOpenSpot(0), m_vertices(NULL), m_edges(NULL){ }

Graph::Graph(uint32_t len) : m_verticesLen(len), m_edgesLen(len*len), m_verticesOpenSpot(0), m_edgesOpenSpot(0){            
    m_vertices = new PartyId[m_verticesLen];
    m_edges = new Edge[m_edgesLen];
}
Graph::~Graph(){
    delete[] m_vertices;
    delete[] m_edges;
}

PartyId* Graph::getVertexPtr(PartyId& id){
    uint32_t idx = IndexOf(id);

    if(MAX_UINT32 == idx){
        ocall_print("Graph::GetVertexPtr - id not found");
        return NULL;        
    }

    return &m_vertices[idx];
}

bool Graph::FindClosestMatch(PartyId& source, std::vector<PartyId*>& path){

    std::queue<PartyId*> Q;
    std::map<PartyId*,PartyId*> backtrace;
    
    PartyId* pSource = getVertexPtr(source);

    if(NULL == pSource){
        ocall_print("FindShortestPath - pSource is NULL");
        return false;
    }

    Q.push(pSource);    

    while(!Q.empty()){
        PartyId* current = Q.front();
        Q.pop();
        
        if(current->Matches(pSource)){

            path.push_back(current);

            while(current != pSource){
                current = backtrace.find(current)->second;
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

        //Add vertex only works when the graph is initialized
    if(m_edges == NULL || m_edgesLen == 0){
        ocall_print("Graph::AddEdge - graph is not initialized");
        return false;
    }

    uint32_t idSrcIdx = this->IndexOf(idSrc);
    if(MAX_UINT32 == idSrcIdx){
        ocall_print("Graph::AddEdge - edge src does not exist");
        return false;
    }

    uint32_t idSinkIdx = this->IndexOf(idSink);
    if(MAX_UINT32 == idSinkIdx){
        ocall_print("Graph::AddEdge - edge sink does not exist");
        return false;
    }

    Edge e(idSrcIdx, idSinkIdx);

    //Edge already in list
    if(this->Contains(e)) return true;

    //Here we know that an edge needs to be added. Is there any room?
    if(m_edgesOpenSpot >= m_edgesLen) {
        ocall_print("Graph::AddEdge - graph is full");
        return false;
    }

    if(!m_vertices[idSrcIdx].AddNeighbor(&m_vertices[idSinkIdx])){
        ocall_print("Graph::AddEdge - failed to add neighbor");
        return false;
    }

    if(!m_vertices[idSinkIdx].AddNeighbor(&m_vertices[idSrcIdx])){
        ocall_print("Graph::AddEdge - failed to add neighbor");
        return false;
    }

    m_edges[m_edgesOpenSpot++] = e;    

    return true;
}

bool Graph::VertexAt(uint32_t idx, PartyId& pid){
    if(m_vertices == NULL || m_verticesLen == 0){
        ocall_print("Graph::VertexAt - graph is not initialized");
        return false;
    }

    if(idx >= m_verticesOpenSpot){
        ocall_print("Graph::VertexAt - invalid index %d", idx);
        return false;
    }

    pid = m_vertices[idx];

    return true;
}

//Inserts id in its ordered position position, keeping the list sorted
bool Graph::AddVertex(PartyId& id){

    //Add vertex only works when the graph is initialized
    if(m_vertices == NULL || m_verticesLen == 0){
        ocall_print("Graph::AddVertex - graph is not initialized");
        return false;
    }

    //Find the position of the first element larger than id
    int position = 0;
    for(; position < m_verticesOpenSpot && id < m_vertices[position]; position++);

    //id is already in list
    if(id == m_vertices[position]) return true;

    //Here we know that a vertex needs to be added. Is there any room?
    if(m_verticesOpenSpot >= m_verticesLen) {
        id.Print();
        ocall_print("Graph::AddVertex - graph is full");
        for(int i = 0; i < m_verticesLen; i++){
            m_vertices[i].Print();
        }
        return false;
    }

    //If the first position is the open spot at the end of the list,
    //we just got the largest id so we put it last
    if(position == m_verticesOpenSpot) {
        m_vertices[m_verticesOpenSpot++] = id;
        return true;
    }

    //id should be inserted in an already taken place so we shift
    //all elements from the taken place to the end of the list
    for(int i = m_verticesOpenSpot; i > position; i--){
        m_vertices[i] = m_vertices[i-1];
        
        //Update edges that touch vertices which changed their index
        for(int j = 0; j < m_edgesOpenSpot; j++){
            if(m_edges[j].GetSrc() == i-1) m_edges[j].SetSrc(i);
            if(m_edges[j].GetSink() == i-1) m_edges[j].SetSink(i);                                              
        }
    }

    m_verticesOpenSpot++;
    m_vertices[position] = id;
    
    return true;
}

bool Graph::GetVertexIterator(VertexIterator& iter){

    if(m_vertices == NULL){
        ocall_print("Graph::GetVertexIterator - graph is not initialized");
        return false;
    }

    iter.SetVertices(m_vertices);
    iter.SetLast(m_verticesOpenSpot == 0 ? 0 : m_verticesOpenSpot-1);

    return true;
}

bool Graph::GetEdgeIterator(EdgeIterator& iter){

    if(m_vertices == NULL){
        ocall_print("Graph::GetEdgeIterator - graph is not initialized");
        return false;
    }

    iter.SetEdges(m_edges);
    iter.SetLast(m_edgesOpenSpot == 0 ? 0 : m_edgesOpenSpot-1);

    return true;
}

uint32_t Graph::IndexOf(PartyId& pid){
    if(m_vertices == NULL){
        ocall_print("Graph::Contains - graph is not initialized");
        return MAX_UINT32;
    }

    VertexIterator iter;

    if(!GetVertexIterator(iter)){
        ocall_print("Graph::Contains - failed to get iterator");
        return MAX_UINT32;
    }

    PartyId currId;
    uint32_t position = 0;
    while(iter.GetNext(currId)){                                        
        if(currId == pid){
            return position;
        }
        position++;
    }

    return MAX_UINT32;
}

uint32_t Graph::IndexOf(Edge& edge){
    if(m_vertices == NULL){
        ocall_print("Graph::Contains - graph is not initialized");
        return MAX_UINT32;
    }

    EdgeIterator iter;

    if(!GetEdgeIterator(iter)){
        ocall_print("Graph::Contains - failed to get iterator");
        return MAX_UINT32;
    }

    Edge currId;
    uint32_t position = 0;
    while(iter.GetNext(currId)){                                        
        if(currId == edge){
            return position;
        }
        position++;
    }

    return MAX_UINT32;
}

bool Graph::Contains(Edge& e){                
    return MAX_UINT32 != IndexOf(e);
}

bool Graph::Contains(PartyId& pid){                
    return MAX_UINT32 != IndexOf(pid);
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

    //Read m_verticesLen PartyIds from buffer
    for(;m_verticesOpenSpot < m_verticesLen; m_verticesOpenSpot++) {
        if(!m_vertices[m_verticesOpenSpot].FromBuffer(buffer, len)){
            ocall_print("Graph::FromBuffer - failed to get all graph elements");
            return false;
        }
    }

    if(m_verticesOpenSpot != m_verticesLen){
        ocall_print("Graph::FromBuffer - m_verticesOpenSpot != m_verticesLen");
        return false;
    }

    if(*len < sizeof(uint32_t)){
        ocall_print("Graph::FromBuffer::m_edgesLen failed, buffer too short, %d", *len);
        return false;
    }

    memcpy(&m_edgesLen, *buffer, sizeof(uint32_t));
    *buffer += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    #ifndef SCHIZZO_TEST
    if(m_edgesLen > MAX_EDGES(m_verticesLen)){
        ocall_print("Graph::FromBuffer - bad value for m_edgesLen %d", m_edgesLen);
        return false;
    }
    #endif

    m_edges = new Edge[m_edgesLen];
    
    //Read m_edgesLen PartyIds from buffer
    for(;m_edgesOpenSpot < m_edgesLen; m_edgesOpenSpot++) {
        if(!m_edges[m_edgesOpenSpot].FromBuffer(buffer, len)){
            ocall_print("Graph::FromBuffer - failed to get all graph elements");
            return false;
        }
    }

    if(m_edgesOpenSpot != m_edgesLen){
        ocall_print("Graph::FromBuffer - m_edgesOpenSpot != m_edgesLen");
        return false;
    }

    ocall_print("Graph::FromBuffer - m_edgesLen is %d", m_edgesLen);
    ocall_print("Graph::FromBuffer - m_verticesLen is %d", m_verticesLen);

    return true;
}

bool Graph::ToBuffer(uint8_t** buffer, size_t* len) {

    if(!IsInitialized()){
        ocall_print("Graph::ToBuffer - called on not initialized graph");
        return false;
    }

    if(*len < sizeof(uint32_t)){
        ocall_print("Graph::ToBuffer - m_verticesOpenSpot failed, buffer too short, %d", *len);
        return false;
    }
    
    memcpy(*buffer, &m_verticesOpenSpot, sizeof(uint32_t));
    *buffer += sizeof(m_verticesOpenSpot);
    *len -= sizeof(m_verticesOpenSpot);

    if(*len < m_verticesOpenSpot*APP_PARTY_FULL_SIZE_BYTES){
        ocall_print("Graph::ToBuffer - m_vertices failed, buffer too short, %d", *len);
        return false;
    }

    //Read m_verticesOpenSpot PartyIds from buffer
    for(int i = 0; i < m_verticesOpenSpot; i++) {
        if(!m_vertices[i].ToBuffer(buffer, len)){
            ocall_print("Graph::FromBuffer - failed to get all graph elements");
            return false;
        }
    }

    if(*len < sizeof(uint32_t)){
        ocall_print("Graph::ToBuffer - m_edgesOpenSpot failed, buffer too short, %d", *len);
        return false;
    }
    
    memcpy(*buffer, &m_edgesOpenSpot, sizeof(uint32_t));
    *buffer += sizeof(m_edgesOpenSpot);
    *len -= sizeof(m_edgesOpenSpot);

    if(*len < m_edgesOpenSpot*EDGE_SIZE_BYTES){
        ocall_print("Graph::ToBuffer - m_edges failed, buffer too short, %d", *len);
        return false;
    }

    //Read m_edgesOpenSpot Edges from buffer
    for(int i = 0; i < m_edgesOpenSpot; i++) {
        if(!m_edges[i].ToBuffer(buffer, len)){
            ocall_print("Graph::FromBuffer - failed to get all graph elements");
            return false;
        }
    }

    return true;
}

void Graph::Print(){
    ocall_print("m_verticesLen: %d", m_verticesLen);
    ocall_print("m_verticesOpenSpot: %d", m_verticesOpenSpot);
    ocall_print("m_edgesLen: %d", m_edgesLen);
    ocall_print("m_edgesOpenSpot: %d", m_edgesOpenSpot);
    for(int i = 0; i < m_verticesOpenSpot; i++){
        ocall_print("===============VERTEX=======================");
        m_vertices[i].Print();
        ocall_print("===============EDGES========================");

        for(int j = 0; j < m_edgesOpenSpot; j++){
            if(m_edges[j].GetSrc() == i){
                m_vertices[m_edges[j].GetSink()].Print();
            }
            if(m_edges[j].GetSink() == i){
                m_vertices[m_edges[j].GetSrc()].Print();
            }
        }
        ocall_print("");
    }

    /*for(int i = 0; i < m_edgesOpenSpot; i++){
        m_edges[i].Print();
    }*/
}

bool Graph::IsEquivalent(Graph* p_other){
    return this->Contains(p_other) && p_other->Contains(this);
}

bool Graph::Contains(Graph* p_other){
    VertexIterator vit;
    EdgeIterator eit;
    PartyId v;
    Edge e;
    if(!p_other->GetVertexIterator(vit) || !p_other->GetEdgeIterator(eit)){
        ocall_print("Graph::IsEquivalent - failed to get iterator");
        return false;
    }
    while(vit.GetNext(v)){
        if(!this->Contains(v)){
            return false;
        }
    }
    while(eit.GetNext(e)){
        if(!this->Contains(e)){
            return false;
        }
    }
    return true; 
}

//TODO: Calculate actual diameter
uint32_t Graph::GetDiameter(){
    return m_verticesLen;
}