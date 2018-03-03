#include "../common_enclave/common_enclave.h"
#include <stdio.h>
#include <assert.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "../GeneralSettings.h"
#include "bb_enclave_t.h"

using namespace std;

void ocall_print(const char* format, uint32_t number){
    char output[500];
    memset(output,0,500);
    snprintf(output, 500, format, number);
    ocall_print(output);
}

void print_buffer(uint8_t* buffer, size_t len){
    char toPrint[len * 3 + 3];
    char* ptr = toPrint;

    snprintf(ptr++,2, "[");

    for(int i = 0; i < len; i++){
        snprintf(ptr, 4, "%02X,", (unsigned char)buffer[i]);
        ptr = ptr + 3;
    }
    
    snprintf(ptr-1, 3, "]");

    ocall_print(toPrint);
}


class BlackBoxExecuter 
{

    class PartyId 
    { 
        public: 
            
            PartyId(){
                memset(m_id, 0, sizeof(m_id));
            }

            /*PartyId(uint8_t* id, size_t size){
                if(PARTY_ID_SIZE_BYTES > size){
                    ocall_print("PartyId::PartyId - id buffer is too short!!");
                    return;
                }
                memcpy(m_id, id, sizeof(m_id));
            }*/

            bool FromBuffer(uint8_t** id, size_t* len){
                return serdes(id, len, false);
            }

            bool ToBuffer(uint8_t** id, size_t* len){
                return serdes(id, len, true);
            }

            PartyId& operator=(const PartyId& rhs){
                memcpy(m_id,&rhs,sizeof(m_id));
                return *this;
            }

            bool operator< (const PartyId& rhs){
                for(int i = 0; i < sizeof(m_id); i++){

                    if(m_id[i] < rhs.m_id[i]){
                        return true;
                    } else if (m_id[i] > rhs.m_id[i]){
                        return false;
                    }
                }

                return false;
            }

            bool operator<= (const PartyId& rhs){                
                return *this < rhs || *this == rhs;
            }

            bool operator==(const PartyId& other){
                return 0==memcmp(m_id, other.m_id, PARTY_ID_SIZE_BYTES);
            }

            bool operator!=(const PartyId& other){
                return !(*this == other);
            }

            void Print(){
                print_buffer(m_id, PARTY_ID_SIZE_BYTES);
            }

            bool isValid(){
                for(int i = 0; i < sizeof(m_id); i++){
                    if(0 != m_id[i]){
                        return true;
                    }
                }
            }

        private:
            bool serdes(uint8_t** id, size_t* len, bool fSer){
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

        private:
            uint8_t m_id[PARTY_ID_SIZE_BYTES];
    };

    class Edge {

        public:
            Edge(): m_idxSrc(MAX_UINT32), m_idxSink(MAX_UINT32) { }
            Edge(uint32_t idxSrc, uint32_t idxSink) : m_idxSrc(idxSrc), m_idxSink(idxSink) { }
            void SetSrc(uint32_t idxSrc) { m_idxSrc = idxSrc; }
            void SetSink(uint32_t idxSink) { m_idxSink = idxSink; }
            bool IsValid() { return (MAX_UINT32 != m_idxSrc) && (MAX_UINT32 != m_idxSink); }
            uint32_t GetSrc() const { return m_idxSrc; }
            uint32_t GetSink() const { return m_idxSink; }

            //This means the graph is undirected
            bool operator==(const Edge& other){
                return (m_idxSrc == other.m_idxSrc && m_idxSink == other.m_idxSink) ||
                       (m_idxSrc == other.m_idxSink && m_idxSink == other.m_idxSrc);
            }

            Edge& operator=(const Edge& rhs){
                m_idxSrc = rhs.m_idxSrc;
                m_idxSink = rhs.m_idxSink;
                return *this;
            }

            bool FromBuffer(uint8_t** buf, size_t* len){
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

            bool ToBuffer(uint8_t** buf, size_t* len){
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
            
            void Print(){
                char buf[EDGE_PRINT_SIZE_BYTES];
                snprintf(buf,EDGE_PRINT_SIZE_BYTES,"[%d,%d]", m_idxSrc, m_idxSink);
                ocall_print(buf);
            }

        private:
            uint32_t m_idxSrc;
            uint32_t m_idxSink;
    };

    class VertexIterator
    {
        public:
            VertexIterator() : m_vertices(NULL), m_current(0), m_last(0) { }

            bool GetNext(PartyId& next){
                if(m_vertices == NULL){
                    ocall_print("VertexIterator::GetNext - iterator not initialized");
                    return false;
                }
                if(m_current >= m_last) {                                       
                    return false;
                }
                next = m_vertices[m_current++];
                return true;
            }

            void SetVertices(PartyId* vertices){ m_vertices = vertices; }
            void SetLast(uint32_t len){ m_last = len; }

        private:
            PartyId* m_vertices;
            uint32_t m_current;
            uint32_t m_last;        
    };

    class EdgeIterator
    {
        public:
            EdgeIterator() : m_edges(NULL), m_current(0), m_last(0) { }

            bool GetNext(Edge& next){
                if(m_edges == NULL){
                    ocall_print("EdgeIterator::GetNext - iterator not initialized");
                    return false;
                }
                if(m_current >= m_last) {                                       
                    return false;
                }
                next = m_edges[m_current++];
                return true;
            }

            void SetEdges(Edge* edges){ m_edges = edges; }
            void SetLast(uint32_t len){ m_last = len; }

        private:
            Edge* m_edges;
            uint32_t m_current;
            uint32_t m_last;        
    };

    class Graph {        

        public: 
            
            Graph() : m_verticesLen(0), m_edgesLen(0), m_verticesOpenSpot(0), m_edgesOpenSpot(0), m_vertices(NULL), m_edges(NULL){ }

            Graph(uint32_t len) : m_verticesLen(len), m_edgesLen(len*len), m_verticesOpenSpot(0), m_edgesOpenSpot(0){            
                m_vertices = new PartyId[m_verticesLen];
                m_edges = new Edge[m_edgesLen];
            }
            ~Graph(){
                delete[] m_vertices;
                delete[] m_edges;
            }

            bool AddEdge(PartyId& idSrc, PartyId& idSink){

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

                m_edges[m_edgesOpenSpot++] = e;
        
                return true;
            }

            bool VertexAt(uint32_t idx, PartyId& pid){
                if(m_vertices == NULL || m_verticesLen == 0){
                    ocall_print("Graph::VertexAt - graph is not initialized");
                    return false;
                }

                if(idx > m_verticesLen){
                     ocall_print("Graph::VertexAt - invalid index %d", idx);
                    return false;
                }

                pid = m_vertices[idx];

                return true;
            }

            //Inserts id in its ordered position position, keeping the list sorted
            bool AddVertex(PartyId& id){

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
                    ocall_print("Graph::AddVertex - graph is full");
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

            bool GetVertexIterator(VertexIterator& iter){

                if(m_vertices == NULL){
                    ocall_print("Graph::GetVertexIterator - graph is not initialized");
                    return false;
                }

                iter.SetVertices(m_vertices);
                iter.SetLast(m_verticesOpenSpot);

                return true;
            }

            bool GetEdgeIterator(EdgeIterator& iter){

                if(m_vertices == NULL){
                    ocall_print("Graph::GetEdgeIterator - graph is not initialized");
                    return false;
                }

                iter.SetEdges(m_edges);
                iter.SetLast(m_edgesOpenSpot);

                return true;
            }

            uint32_t IndexOf(PartyId& pid){
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

            uint32_t IndexOf(Edge& edge){
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

            bool Contains(Edge& e){                
                return MAX_UINT32 != IndexOf(e);
            }

            bool Contains(PartyId& pid){                
                return MAX_UINT32 != IndexOf(pid);
            }

            uint32_t GetSize() const {
                return m_verticesOpenSpot;
            }

            bool IsInitialized() const {
                return m_vertices != NULL;
            }

            bool FromBuffer(uint8_t** buffer, size_t* len) {

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

                if(*len < sizeof(uint32_t)){
                    ocall_print("Graph::FromBuffer::m_edgesLen failed, buffer too short, %d", *len);
                    return false;
                }

                memcpy(&m_edgesLen, *buffer, sizeof(uint32_t));
                *buffer += sizeof(uint32_t);
                *len -= sizeof(uint32_t);

                if(m_edgesLen > m_verticesLen*m_verticesLen){
                    ocall_print("Graph::FromBuffer - bad value for m_edgesLen %d", m_edgesLen);
                    return false;
                }

                m_edges = new Edge[m_edgesLen];
                
                //Read m_edgesLen PartyIds from buffer
                for(;m_edgesOpenSpot < m_edgesLen; m_edgesOpenSpot++) {
                    if(!m_edges[m_edgesOpenSpot].FromBuffer(buffer, len)){
                        ocall_print("Graph::FromBuffer - failed to get all graph elements");
                        return false;
                    }
                }

                return true;
            }

            bool ToBuffer(uint8_t** buffer, size_t* len) {

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

                if(*len < m_verticesOpenSpot*PARTY_ID_SIZE_BYTES){
                    ocall_print("Graph::ToBuffer - m_vertices failed, buffer too short, %d", *len);
                    return false;
                }

                //Read m_verticesLen PartyIds from buffer
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

                //Read m_verticesLen PartyIds from buffer
                for(int i = 0; i < m_edgesOpenSpot; i++) {
                    if(!m_edges[i].ToBuffer(buffer, len)){
                        ocall_print("Graph::FromBuffer - failed to get all graph elements");
                        return false;
                    }
                }

                return true;
            }

            void Print(){
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

            bool IsEquivalent(Graph* p_other){
                return this->Contains(p_other) && p_other->Contains(this);
            }
            
            bool Contains(Graph* p_other){
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
            uint32_t GetDiameter(){
                return m_verticesLen;
            }

        private:
            uint32_t m_verticesLen;
            uint32_t m_verticesOpenSpot;
            PartyId* m_vertices;

            Edge* m_edges;
            uint32_t m_edgesLen;
            uint32_t m_edgesOpenSpot;
    };

    typedef enum _eThcMsgType {
        THC_MSG_NONE = 0,
        THC_MSG_COLLECTION,
        THC_MSG_CONSISTENCY
    } eThcMsgType;


public:
    BlackBoxExecuter() : m_fIsInitialized(false),
                         m_fIsSecretSet(false),
                         m_abortedRound(MAX_UINT32), 
                         m_numOfVertices(0),
                         m_numOfNeighbors(0),                         
                         m_ctrRound(0),
                         m_abortCounter(0),
                         //m_ctrNeighbor(0),
                         m_pGraph(NULL),
                         m_pNeighbors(NULL),
                         m_pRoundChecklist(NULL)


    {
        memset(m_s, 0, sizeof(m_s));            
    }

    ~BlackBoxExecuter()
    {
        memset(m_s, 0, sizeof(m_s));
        delete m_pGraph;
        delete m_pNeighbors;
        delete m_pRoundChecklist;
    }

    bool Initialize(uint32_t numOfNeighbors, uint32_t numOfVertices) 
    {
        uint8_t localIdBuf[PARTY_ID_SIZE_BYTES];
        size_t localIdSize = PARTY_ID_SIZE_BYTES;
        uint8_t* bufPtr = localIdBuf;

        if(numOfNeighbors > numOfVertices){
            ocall_print("BlackBoxExecuter::Initialize - numOfNeighbors > numOfVertices");
            return false;
        }

        //Use SGX hardware randomness to generate a local ID string
        sgx_status_t status = sgx_read_rand((unsigned char*)bufPtr, localIdSize);        
        
        if(status) {
            ocall_print("BlackBoxExecuter::Initialize - sgx_read_rand status is %d\n", status);
            return false;
        }

        if(!m_localId.FromBuffer(&bufPtr, &localIdSize)) {
            ocall_print("BlackBoxExecuter::Initialize -failed to parse id from buffer");
            return false;
        }

        m_numOfVertices = numOfVertices;
        m_numOfNeighbors = numOfNeighbors;

        m_pGraph = new Graph(m_numOfVertices);

        m_pGraph->AddVertex(m_localId);

        //+1 because we also store the local is in the neighbors graph
        m_pNeighbors = new Graph(m_numOfNeighbors + 1);
        m_pNeighbors->AddVertex(m_localId);

        m_pRoundChecklist = new Graph(m_numOfNeighbors);

        return m_fIsInitialized = true;
    }
    
    bool IsSecretSet() const {
        return m_fIsSecretSet;    
    }

    bool IsInitialized() const {
        return m_fIsInitialized;
    }

    bool IsReady() const {
        return IsInitialized() && IsSecretSet();
    }

    bool SetSecret(uint8_t s[SECRET_KEY_SIZE_BYTES], size_t size)
    {
        if(SECRET_KEY_SIZE_BYTES != size) {
            ocall_print("BlackBoxExecuter::SetSecret - secret size different from expected, %d", size);
            return false;
        }

        memcpy(m_s, s, SECRET_KEY_SIZE_BYTES);
        
        return m_fIsSecretSet = true;
    }

    bool GenerateFirstMessage(uint8_t* B_out, size_t B_out_size){

        if(THC_ENCRYPTED_MSG_SIZE_BYTES != B_out_size){
            ocall_print("BlackBoxExecuter::GenerateFirstMessage - wrong buffer size");
            return false;
        }

        if(0 != m_ctrRound){
            ocall_print("BlackBoxExecuter::GenerateFirstMessage - not first round");
            return false;
        }

        m_ctrRound++;

        if(!generateCollectionMessage(B_out, B_out_size)){
            ocall_print("BlackBoxExecuter::GenerateFirstMessage - Failed to generate collection message");
            return false;
        }        

        return true;
    }

    bool processAbort(uint8_t* B_out, size_t B_out_size){
        if(MAX_UINT32 == m_abortedRound){
            m_abortedRound = m_ctrRound;
        }
        
        ocall_print("ABORT!!!!");
        m_abortCounter++;

        ocall_print("m_abortCounter = %d", m_abortCounter);
        ocall_print("m_pRoundChecklist->GetSize() = %d", m_pRoundChecklist->GetSize());
        ocall_print("m_numOfNeighbors = %d", m_numOfNeighbors);

        if(m_abortCounter + m_pRoundChecklist->GetSize() == m_numOfNeighbors){
            if(!incrementRound(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::updateAbort - failed to increment round");
                return false;
            }
        }

        return true;
    }

    /*Called upon dequeue from incoming message queue. B_in is the encrypted payload from a neighbor, B_out is 
        1. Last neighbor in last round of consistency checking - the result of the calculated function or abort.
        2. Last neighbor in other rounds - the encrypted payload to send to the neighbors in the next round.
        3. Otherwise - NULL*/

    bool Execute(uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size)
    {

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::Execute - not ready");
            return false;
        }

        //This means abort
        if(0 == B_in_size){
            
            if(!processAbort(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::Execute - failed to process abort");
                return false;
            }

            return true;
        }

        if(THC_ENCRYPTED_MSG_SIZE_BYTES != B_in_size){
            ocall_print("BlackBoxExecuter::Execute - wrong input buffer size, %d", B_in_size);
            return false;
        }
        
        //We should know all graph vertices in d (=diameter) rounds, and d < N (=m_numOfVertices)
        if((m_pGraph->GetSize() < m_numOfVertices) && (m_ctrRound > m_numOfVertices)){
            ocall_print("m_ctrRound > m_numOfVertices, yet graph is incomlete");
            return false;
        }

        uint8_t decrypted[THC_PLAIN_MSG_SIZE_BYTES];
        uint8_t* decryptedPtr = decrypted;
        size_t decryptedLen = THC_PLAIN_MSG_SIZE_BYTES;

        sgx_status_t status = decrypt(decrypted, sizeof(decrypted), B_in, m_s);

        if(SGX_SUCCESS != status){
            ocall_print("failed to decrypt B_in, status is %d", status);

            /*if(!processAbort(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::Execute - failed to process abort");
                return false;
            }*/

            return false; 
        }

        eThcMsgType type;        

        if(!extractAndVerityMsgType(&decryptedPtr, &decryptedLen, type)) return false;        
        if(!consumeRoundNumber(&decryptedPtr, &decryptedLen)) return false;
        if(!consumePartyId(&decryptedPtr, &decryptedLen)) return false;

        //m_ctrNeighbor++;

        //ocall_print("=========m_ctrNeighbor=%d===============", m_ctrNeighbor);

        //This means we are in the graph collection phase
        if(THC_MSG_COLLECTION == type && m_ctrRound <= m_numOfVertices) { 
            
            if(!consumeGraph(&decryptedPtr, &decryptedLen)) {
                ocall_print("BlackBoxExecuter::Execute - failed to consume graph");
                return false;
            }                

        } else if (THC_MSG_CONSISTENCY == type) {
        //This means we are in the consistency checking phase

            if(!consumeAbort(&decryptedPtr, &decryptedLen)){
                ocall_print("BlackBoxExecuter::Execute - failed to consume abort");
                return false;
            }

        } else {
            ocall_print("BlackBoxExecuter::Execute - invalid message type");
            return false;
        }

        //This means we just recieved a message from the last neighbor of this round
        if(m_abortCounter + m_pRoundChecklist->GetSize() == m_numOfNeighbors){

            if(!incrementRound(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::Execute - incrementRound failed");
                return false;
            }          
        }
        
        return true;
    }

    bool incrementRound(uint8_t* B_out, size_t B_out_size){

        //When we recieve a message from the last neighbor we finish the round
        m_ctrRound++;

        m_abortCounter = 0;        
        delete m_pRoundChecklist;
        m_pRoundChecklist = new Graph(m_numOfNeighbors);

        if(!generateOutput(B_out, B_out_size)){
            ocall_print("BlackBoxExecuter::Execute - Failed to generate output");
            return false;
        }

        return true; 
    }

    void Print(){

        ocall_print("secret key is:");
        print_buffer(m_s, SECRET_KEY_SIZE_BYTES);
        ocall_print(m_fIsInitialized ? "m_fIsInitialized = true" : "m_fIsInitialized = false");
        ocall_print(m_fIsSecretSet ? "m_fIsSecretSet = true" : "m_fIsSecretSet = false");
        ocall_print("m_abortedRound is %d", m_abortedRound);
        ocall_print("local id is:");
        m_localId.Print();
        ocall_print("m_numOfVertices = %d", m_numOfVertices);
        ocall_print("Graph is:");
        if(NULL != m_pGraph){
            m_pGraph->Print();
        } else{
            ocall_print("Graph is NULL");
        }        
        ocall_print("m_numOfNeighbors = %d", m_numOfNeighbors);
        ocall_print("m_ctrRound = %d", m_ctrRound);
        ocall_print("m_pRoundChecklist->GetSize() = %d", m_pRoundChecklist->GetSize());
    }

    bool CompareGraph(BlackBoxExecuter& other){
        return m_pGraph->IsEquivalent(other.m_pGraph);
    }

private:

    bool generateOutput(uint8_t* B_out, size_t B_out_size){

         ocall_print("BlackBoxExecuter::generateOutput - start");
         if(!IsReady()){
            ocall_print("BlackBoxExecuter::generateOutput - not ready");
            return false;
         }

        //This means we are in the last round of consistency checking
        if(m_ctrRound >= m_numOfVertices + m_numOfVertices*m_pGraph->GetDiameter()){

            ocall_print("BlackBoxExecuter::generateOutput - result");
            if(!calculateResult(B_out, B_out_size)){
                ocall_print("BlackBoxExeuter::generateOutput - failed to calculate result");
                return false;
            }

        } else if(m_ctrRound < m_pGraph->GetDiameter()) { 
        //This means we are in the graph collection phase
            ocall_print("BlackBoxExecuter::generateOutput - collection");
            if(!generateCollectionMessage(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::generateOutput - failed to generate collection message");
                return false;
            }

        } else {
        //This means we are in the consistency checking phase
            ocall_print("BlackBoxExecuter::generateOutput - consisntency");
            if(!generateConsistencyMessage(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::generateOutput - failed to generate consistency message");
                return false;
            }
        }

        ocall_print("BlackBoxExecuter::generateOutput - done");

        return true;
    }

    bool updateGraph(Graph& graph){

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::updateGraph - not ready");
            return false;
        }

        VertexIterator vi;
        PartyId pid;

        if(!graph.GetVertexIterator(vi)){
            ocall_print("BlackBoxExecuter::UpdateGraph - failed to get iterator for graph in message");
            return false;
        }

        //Add all new vertices
        while(vi.GetNext(pid)) m_pGraph->AddVertex(pid);        

        EdgeIterator ei;
        Edge e;

        if(!graph.GetEdgeIterator(ei)){
            ocall_print("BlackBoxExecuter::UpdateGraph - failed to get iterator for graph in message");
            return false;
        }

        PartyId srcPid, sinkPid;

        //Add all new edges
        while(ei.GetNext(e)){
            if(!graph.VertexAt(e.GetSrc(), srcPid)){
                ocall_print("BlackBoxExecuter::updateGraph - failed to find src vertex at %d", e.GetSrc());
                return false;
            }
            if(!graph.VertexAt(e.GetSink(), sinkPid)){
                ocall_print("BlackBoxExecuter::updateGraph - failed to find sink vertex at %d", e.GetSink());
                return false;
            }

            if(!m_pGraph->AddEdge(srcPid, sinkPid)){
                ocall_print("BlackBoxExecuter::updateGraph - failed to add edge");
                return false;
            }
        }

        return true;
    }

    bool outputAbort(uint8_t* B_out, size_t B_out_size){
        if(sizeof(ABORT_MESSAGE) > B_out_size){
            ocall_print("BlackBoxExecuter::calculateResult - B_out_size smaller than abort message, %d", B_out_size);
            return false;
        }

        if(sizeof(ABORT_MESSAGE)-1 != snprintf((char*)B_out, sizeof(ABORT_MESSAGE), "%s", ABORT_MESSAGE)){
            ocall_print("BlackBoxExecuter::calculateResult - failed to print abort message");
            return false;
        }
        return true;
    }

    bool outputResult(uint8_t* B_out, size_t B_out_size){
        if(sizeof(DEBUG_RESULT_MESSAGE) > B_out_size){
            ocall_print("BlackBoxExecuter::calculateResult - B_out_size smaller than result message, %d", B_out_size);
            return false;
        }
        if(sizeof(DEBUG_RESULT_MESSAGE)-1 != snprintf((char*)B_out, sizeof(DEBUG_RESULT_MESSAGE), "%s", DEBUG_RESULT_MESSAGE)){
            ocall_print("BlackBoxExecuter::calculateResult - failed to print result message");
            return false;
        }
        return true;
    }

    bool calculateResult(uint8_t* B_out, size_t B_out_size)
    {

        ocall_print("calculate result");
        if(!IsReady()){
            ocall_print("BlackBoxExecuter::calculateResult - not ready");
            return false;
        }

        if(MAX_UINT32 == m_abortedRound){
            return outputResult(B_out, B_out_size);
        }

        if(m_abortedRound < m_pGraph->GetDiameter()){
            return outputAbort(B_out, B_out_size);
        }

        //We return result if we first saw an abort after the i'th subphase of consistency checking,
        //i being our index.
        uint32_t consistencyCheckingRounds = m_abortedRound - m_pGraph->GetDiameter();
        uint32_t subphase = (consistencyCheckingRounds + 1) / m_numOfVertices;
        uint32_t i = m_pGraph->IndexOf(m_localId);

        ocall_print("BlackBoxExecuter::calculateResult - subphase is %d", subphase);
        ocall_print("BlackBoxExecuter::calculateResult - i is %d", i);

        if(i < subphase){            
            return outputResult(B_out, B_out_size);
        }

        return outputAbort(B_out, B_out_size);
    }

    bool generateThcMessage(uint8_t** buffer, size_t* len, eThcMsgType msgType){

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::generateThcMessage - not ready");
            return false;
        }

        if(THC_PLAIN_MSG_SIZE_BYTES != *len){
            ocall_print("BlackBoxExecuter::generateThcMessage - wrong buffer size, %d", *len);
            return false;
        }


        if(*len < sizeof(msgType)){
            ocall_print("BlackBoxExecuter::generateThcMessage - buffer too small to serialize msg type");
            return false;
        }
        
        //Serialize msg type (4B)
        memcpy(*buffer, &msgType, sizeof(msgType));
        *buffer += sizeof(msgType);
        *len -= sizeof(msgType);

        if(*len < sizeof(m_ctrRound)){
            ocall_print("BlackBoxExecuter::generateThcMessage - buffer too small to serialize m_ctrRound");
            return false;
        }

        //Serialize the round (4B)        
        memcpy(*buffer, &m_ctrRound, sizeof(m_ctrRound));
        *buffer += sizeof(m_ctrRound);
        *len -= sizeof(m_ctrRound);

        if(!m_localId.ToBuffer(buffer, len)){
            ocall_print("BlackBoxExecuter::generateThcMessage - failed to serialize m_localId");
            return false;
        }

        return true;
    }

    bool generateConsistencyMessage (uint8_t* B_out, size_t B_out_size){

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::generateConsistencyMessage - not ready");
            return false;
        }

        if(THC_ENCRYPTED_MSG_SIZE_BYTES != B_out_size){
            ocall_print("BlackBoxExecuter::generateConsistencyMessage - wrong buffer size, %d", B_out_size);
            return false;
        }

        uint8_t buffer[THC_PLAIN_MSG_SIZE_BYTES];
        uint8_t* bufferPtr = buffer;
        size_t bufferLength = THC_PLAIN_MSG_SIZE_BYTES;
        memset(buffer, 0, sizeof(buffer));

        if(!generateThcMessage(&bufferPtr, &bufferLength, THC_MSG_CONSISTENCY)){
            ocall_print("BlackBoxExecuter::generateConsistencyMessage - failed to generate message");
            return false;
        }

        bool fAbort = (MAX_UINT32 != m_abortedRound);
        if(bufferLength < sizeof(fAbort)){
            ocall_print("BlackBoxExecuter::generateThcMessage - buffer too small to serialize msg type");
            return false;
        }
        
        //Serialize m_fAbort (4B)
        memcpy(bufferPtr, &fAbort, sizeof(fAbort));

        sgx_status_t status;
        if(SGX_SUCCESS != (status = encrypt(buffer, THC_PLAIN_MSG_SIZE_BYTES,B_out, m_s))){
            ocall_print("BlackBoxExecuter::generateConsistencyMessage - failed to encrypt collection message, %d", status);
            return false;
        }

        return true;
    }

    /*
    
    MsgType(4B),RoundNumber(4B),LocalId(16B),Graph{Length(4B), Length*16B}, Padding(N-Length * 16B)

    */

    bool generateCollectionMessage (uint8_t* B_out, size_t B_out_size){

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - not ready");
            return false;
        }

        if(THC_ENCRYPTED_MSG_SIZE_BYTES != B_out_size){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - wrong buffer size, %d", B_out_size);
            return false;
        }

        uint8_t buffer[THC_PLAIN_MSG_SIZE_BYTES];
        uint8_t* bufferPtr = buffer;
        size_t bufferLength = THC_PLAIN_MSG_SIZE_BYTES;
        memset(buffer, 0, sizeof(buffer));

        if(!generateThcMessage(&bufferPtr, &bufferLength, THC_MSG_COLLECTION)){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to generate message");
            return false;
        }

        if(!m_pGraph->ToBuffer(&bufferPtr, &bufferLength)){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to serialize graph");
            return false;
        }

        sgx_status_t status;
        if(SGX_SUCCESS != (status = encrypt(buffer, THC_PLAIN_MSG_SIZE_BYTES,B_out, m_s))){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to encrypt collection message, %d", status);
            return false;
        }

        return true;
    }

    bool extractAndVerityMsgType(uint8_t** msg, size_t* len, eThcMsgType& type) {

        if(*len < sizeof(eThcMsgType)){
            ocall_print("BlackBoxExecuter::extractAndVerityMsgType failed, buffer too short, %d", *len);
            return false;
        }

        memcpy(&type, *msg, sizeof(eThcMsgType));
        *msg += sizeof(eThcMsgType);
        *len -= sizeof(eThcMsgType);

        if(THC_MSG_COLLECTION != type && THC_MSG_CONSISTENCY != type){
            ocall_print("BlackBoxExecuter::extractAndVerityMsgType - invalid message type");
            return false;
        }

        return true;

    }

    bool consumeRoundNumber(uint8_t** msg, size_t* len) {
        
        uint32_t roundNumber;
        if(*len < sizeof(uint32_t)){
            ocall_print("BlackBoxExecuter::consumeRoundNumber failed, buffer too short, %d", *len);
            return false;
        }

        memcpy(&roundNumber, *msg, sizeof(uint32_t));
        *msg += sizeof(uint32_t);
        *len -= sizeof(uint32_t);

        if(THC_MAX_NUMBER_OF_ROUNDS < roundNumber){
            ocall_print("BlackBoxExecuter::consumeRoundNumber failed, invalid round number %d", roundNumber);
            return false;
        }

        if(roundNumber != m_ctrRound){
            ocall_print("BlackBoxExecuter::consumeRoundNumber - received a message with the wrong round number %d", roundNumber);
            return false;
        }

        return true;
    }

    bool consumePartyId(uint8_t** msg, size_t* len) {

        PartyId neighborId;

        if(!neighborId.FromBuffer(msg, len)){
            ocall_print("BlackBoxExecuter::consumePartyId failed");
            return false;
        }

        if(neighborId == m_localId){
            ocall_print("BlackBoxExecuter::consumePartyId - got a message with local id");
            return false;
        }

        if(m_pRoundChecklist->Contains(neighborId)){
            ocall_print("BlackBoxExecuter::consumePartyId - already received a message fom this neighbor in this round");
            return false;
        }

        if(!m_pNeighbors->AddVertex(neighborId)){
            ocall_print("BlackBoxExecuter::consumePartyId - failed to add vertex for neighbor");
            return false;
        }

        if(!m_pNeighbors->AddEdge(m_localId, neighborId)){
            ocall_print("BlackBoxExecuter::consumePartyId - failed to add edge to neighbor");
            return false;
        }

        if(!updateGraph(*m_pNeighbors)){
            ocall_print("BlackBoxExecuter::consumePartyId - failed to update graph");
            return false;
        }

        if(!m_pRoundChecklist->AddVertex(neighborId)){
            ocall_print("BlackBoxExecuter::consumePartyId - failed to add vertex for neighbor to checklist");
            return false;
        }

        return true;
    }

    bool consumeAbort(uint8_t** msg, size_t* len){
        
        bool fAbort;

        if(*len < sizeof(fAbort)){
            ocall_print("BlackBoxExecuter::consumeAbort failed, buffer too short, %d", *len);
            return false;
        }
        
        memcpy(&fAbort, *msg, sizeof(fAbort));
        *msg += sizeof(fAbort);
        *len -= sizeof(fAbort);

        if(fAbort){
            if(MAX_UINT32 == m_abortedRound){
                m_abortedRound = m_ctrRound;
            }
        }        

        return true;
    }

    bool consumeGraph(uint8_t** msg, size_t* len){
        Graph graph;

        if(!graph.FromBuffer(msg, len)) {
            ocall_print("BlackBoxExecuter::consumeGraph failed");
            return false;
        }

        if(!updateGraph(graph)){
                ocall_print("failed to update graph");
                return false;
        }

        return true;
    }

private:
    uint8_t m_s[SECRET_KEY_SIZE_BYTES];
    bool m_fIsInitialized;
    bool m_fIsSecretSet;
    uint32_t m_abortedRound;

    PartyId m_localId;
    uint32_t m_numOfVertices;
    Graph* m_pGraph;
    Graph* m_pNeighbors;
    Graph* m_pRoundChecklist;
    size_t m_numOfNeighbors;
    uint32_t m_ctrRound;
    uint32_t m_abortCounter;
    //uint32_t m_ctrNeighbor;
};

/*BB enclave internal data*/
uint8_t k[SECRET_KEY_SIZE_BYTES];
sgx_ec256_private_t bb_priv_key;
BlackBoxExecuter bbx;
uint32_t* graph_ids = NULL;

/***
[Initialization-step 1: input pk, attestation quote Q']
1. Verify that Q' is a valid Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode"
2. Generate an encryption key pair (bbpk, bbsk), output bbpk.
3. Compute k=DH(bbsk, pk) the shared DH key of skg and bb
4. Use the "independent attestation" mechanism to generate an Intel-signed quote that "bbpk was generated by [X-Black-Box Enclave] running in secure mode". This is Q, output.
5. Seal (k) [sealing to MRENCLAVE] and output the sealed data.
***/
sgx_status_t bb_init_1(sgx_sealed_data_t* p_sealed_data, size_t sealed_size, 
                       sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size,
                       uint32_t num_of_neighbors, uint32_t num_of_vertices) {


    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    if(!bbx.Initialize(num_of_neighbors, num_of_vertices)){
        ocall_print("bb_init_1 - bbx failed to initialize");
        return status;
    }
    
    memset(k, 0, sizeof(k));

    //Compute k=DH(bbsk, pk) the shared DH key of skg and bb
    sgx_ecc_state_handle_t handle;

    status = sgx_ecc256_open_context(&handle);
    
    if(status) {
        ocall_print("sgx_ecc256_open_context status is %d\n", status);
        return status;
    }
    
    status = sgx_ecc256_create_key_pair(&bb_priv_key, p_bb_pk, handle);
    
    if(status) {
        ocall_print("sgx_ecc256_create_key_pair status is %d\n", status);
        return status;
    } 
    
    sgx_ec256_dh_shared_t shared_key;
    status = sgx_ecc256_compute_shared_dhkey(&bb_priv_key,p_skg_pk,&shared_key, handle);
    
    if(status){
        ocall_print("sgx_ecc256_compute_shared_dhkey status is %d\n", status);
        return status;
    } 

    //shared_key is k
    memcpy(k ,&shared_key, SECRET_KEY_SIZE_BYTES);

    //Seal (k) [sealing to MRENCLAVE]
    status = sgx_seal_data(0, NULL, sizeof(k), k, sealed_size, p_sealed_data);
    
    if(status){
        ocall_print("sgx_seal_data status is %d\n", status);
        return status;
    }

    return SGX_SUCCESS;

    }

/***
[Initialization-step 2: input sealed data (k), ciphertext c']
1. Unseal k
2. Decrypt c' with k to get s
3. Seal (s) [to MRENCLAVE] and output sealed data.
***/
sgx_status_t bb_init_2(sgx_sealed_data_t* p_sealed_k,                       //in (Seal(k))
                       uint8_t* s_encrypted, size_t s_encrypted_size,       //in (c')
                       sgx_sealed_data_t* p_sealed_s, size_t sealed_size)  //out (Seal(s))
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    //Unseal k
    uint8_t k_unsealed[SECRET_KEY_SIZE_BYTES];
    uint32_t unsealed_text_length = sizeof(k_unsealed);

    status = sgx_unseal_data(p_sealed_k,
                             NULL,
                             0,
                             k_unsealed, 
                             &unsealed_text_length);
                             
    
    if(status){
        ocall_print("sgx_unseal_data status is %d\n", status);
        return status;
    }

    //TODO-remove
    //ocall_print("k=k_unsealed? %d\n", memcmp(k_unsealed, k, SECRET_KEY_SIZE_BYTES));

    uint8_t s_decrypted[SECRET_KEY_SIZE_BYTES];
    memset(s_decrypted, 0, SECRET_KEY_SIZE_BYTES);

    //Decrypt c' with k to get s
    status = decrypt(s_decrypted, SECRET_KEY_SIZE_BYTES, s_encrypted,k_unsealed);
    
    if(status){
        ocall_print("decrypt status is %d\n", status);
        return status;
    }

    if(!bbx.SetSecret(s_decrypted, SECRET_KEY_SIZE_BYTES)){
            ocall_print("bb_init_2 - failed to set secret");
            return status;
    }

    //Seal (s) [to MRENCLAVE] and output sealed data.
    status = sgx_seal_data(0, NULL, sizeof(s_decrypted), s_decrypted, sealed_size, p_sealed_s);
    
    if(status) {
        ocall_print("sgx_seal_data status is %d\n", status);
        return status;
    } 

    return SGX_SUCCESS;
}


sgx_status_t bb_re_init(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, uint32_t num_of_neighbors, uint32_t num_of_vertices){

    if(!bbx.Initialize(num_of_neighbors, num_of_vertices)){
        ocall_print("bb_re_init - Initialize failed");
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t s_unsealed[SECRET_KEY_SIZE_BYTES];
    uint32_t unsealed_text_length = sizeof(s_unsealed);
    sgx_status_t status;
    status = sgx_unseal_data(p_sealed_s,
                             NULL,
                             0,
                             s_unsealed, 
                             &unsealed_text_length);
                             
    
    if(status){
        ocall_print("bb_re_init - failed to unseal s, status is %d\n", status);
        return status;
    }

    if(!bbx.SetSecret(s_unsealed, SECRET_KEY_SIZE_BYTES)){
        ocall_print("bb_re_init - SetSecret failed");
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}


sgx_status_t bb_get_result(uint8_t* B_out, size_t B_out_size) {

    /*if(!bbx.GetResult(B_out, B_out_size)){
        ocall_print("bb_get_result - failed to get result");
        return SGX_ERROR_UNEXPECTED;        
    }*/

    return SGX_SUCCESS;
}

sgx_status_t bb_generate_first_msg(uint8_t* B_out, size_t B_out_size) {

    if(!bbx.IsReady()){
        ocall_print("bb_generate_first_msg - bbx not ready");
        return SGX_ERROR_UNEXPECTED;
    }

    if(!bbx.GenerateFirstMessage(B_out, B_out_size)){
        ocall_print("bb_generate_first_msg - failed to generate first msg");
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

sgx_status_t bb_re_init(sgx_sealed_data_t* p_sealed_s, size_t sealed_size){

}

/*
[Execution: input memory buffer B_in]
1. Execute B_out=X_s(B_in)
3. Output B_out
*/
sgx_status_t bb_exec(uint8_t* B_in, size_t B_in_size,                   //in (B_in)
                     uint8_t* B_out, size_t B_out_size)                 //out (B_out)
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    
    if(!bbx.IsReady()){
        ocall_print("bb_exec - bbx not ready");
        return status;
    }

    if(!bbx.Execute(B_in, B_in_size, B_out, B_out_size)){
        ocall_print("bb_exec - failed to execute");
        return status;
    }

    bbx.Print();

    return SGX_SUCCESS;
}

sgx_status_t derive_smk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                        sgx_ec_key_128bit_t* p_smk, size_t smk_size) {

    return _derive_smk(p_pk, pk_size, p_smk,smk_size, &bb_priv_key);

}