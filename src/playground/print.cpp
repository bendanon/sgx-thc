#include <stdio.h>
#include <string.h>

#include "/home/ben/Projects/sgx/sgx-thc/src/th_definitions.h"
#include <stdlib.h>

typedef unsigned int sgx_status_t;

#define SGX_AESGCM_KEY_SIZE 32
#define SGX_SUCCESS 0

sgx_status_t sgx_read_rand(unsigned char *randbuf, size_t length_in_bytes){

    for(int i = 0; i < length_in_bytes; i++){
        randbuf[i] = rand();
    }
    return SGX_SUCCESS;

}

sgx_status_t encrypt(uint8_t* plaintext, size_t plaintext_size,  
                         uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE]){
                            memcpy(ciphertext, plaintext, plaintext_size);
                            return 0;
                         }

sgx_status_t decrypt(uint8_t* plaintext, size_t plaintext_size,
                         uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE]){
                             memcpy(plaintext, ciphertext, plaintext_size);
                             return 0;
                         }


void ocall_print(const char* format, uint32_t number){
    char output[500];
    memset(output,0,500);
    snprintf(output, 500, format, number);
    printf("%s\n", output);
}
void ocall_print(const char* format){
    printf("%s\n", format);
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

    class GraphIterator
    {
        public:
            GraphIterator() : m_ids(NULL), m_current(0), m_last(0) { }

            bool GetNext(PartyId& next){
                if(m_ids == NULL){
                    ocall_print("GraphIterator::GetNext - iterator not initialized");
                    return false;
                }
                if(m_current >= m_last) {                                       
                    return false;
                }
                next = m_ids[m_current++];
                return true;
            }

            void SetIds(PartyId* ids){ m_ids = ids; }
            void SetLast(uint32_t len){ m_last = len; }

        private:
            PartyId* m_ids;
            uint32_t m_current;
            uint32_t m_last;        
    };

    class Graph {        

        public: 
            
            Graph() : m_len(0), m_openSpot(0), m_ids(NULL){ }

            Graph(uint32_t len) : m_len(len), m_openSpot(0){            
                m_ids = new PartyId[m_len];
            }
            ~Graph(){
                delete m_ids;
            }
            bool AddVertex(PartyId& id){

                //Add vertex only works when the graph is initialized
                if(m_ids == NULL || m_len == 0){
                    ocall_print("Graph::AddVertex - graph is not initialized");
                    return false;
                }

                //When m_openSpot == m_len, the graph is full
                if(m_openSpot >= m_len) {
                    ocall_print("Graph::AddVertex - graph is full");
                    return false;
                }
                m_ids[m_openSpot++] = id;
                return true;
            }

            bool GetIterator(GraphIterator& iter){

                if(m_ids == NULL){
                    ocall_print("Graph::GetIterator - graph is not initialized");
                    return false;
                }

                iter.SetIds(m_ids);
                iter.SetLast(m_openSpot);

                return true;
            }

            bool Contains(PartyId& pid){
                if(m_ids == NULL){
                    ocall_print("Graph::Contains - graph is not initialized");
                    return false;
                }

                GraphIterator iter;

                if(!GetIterator(iter)){
                    ocall_print("Graph::Contains - failed to get iterator");
                    return false;
                }

                PartyId currId;

                while(iter.GetNext(currId)){
                    if(currId == pid){
                        return true;
                    }
                }

                return false;
            }

            uint32_t GetLength() const {
                return m_openSpot;
            }

            bool IsInitialized() const {
                return m_ids != NULL;
            }

            bool FromBuffer(uint8_t** buffer, size_t* len) {

                if(IsInitialized()){
                    ocall_print("Graph::ToBuffer - called on initialized graph");
                    return false;
                }

                if(*len < sizeof(uint32_t)){
                    ocall_print("Graph::FromBuffer::m_len failed, buffer too short, %d", *len);
                    return false;
                }
                
                memcpy(&m_len, *buffer, sizeof(uint32_t));
                *buffer += sizeof(uint32_t);
                *len -= sizeof(uint32_t);

                if(m_len > MAX_GRAPH_SIZE){
                    ocall_print("Graph::FromBuffer - bad value for m_len %d", m_len);
                    return false;
                }

                m_ids = new PartyId[m_len];

                //Read m_len PartyIds from buffer
                for(;m_openSpot < m_len; m_openSpot++) {
                    if(!m_ids[m_openSpot].FromBuffer(buffer, len)){
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
                    ocall_print("Graph::FromBuffer::m_len failed, buffer too short, %d", *len);
                    return false;
                }
                
                memcpy(*buffer, &m_openSpot, sizeof(uint32_t));
                *buffer += sizeof(m_openSpot);
                *len -= sizeof(m_openSpot);

                if(m_len > MAX_GRAPH_SIZE){
                    ocall_print("Graph::ToBuffer - bad value for m_len %d", m_len);
                    return false;
                }

                //Read m_len PartyIds from buffer
                for(int i = 0; i < m_openSpot; i++) {
                    if(!m_ids[i].ToBuffer(buffer, len)){
                        ocall_print("Graph::FromBuffer - failed to get all graph elements");
                        return false;
                    }
                }

                return true;
            }

            void Print(){
                ocall_print("m_len: %d", m_len);
                ocall_print("m_openSpot: %d", m_openSpot);
                for(int i = 0; i < m_openSpot; i++){
                    m_ids[i].Print();
                }
            }

            //TODO: Calculate actual diameter
            uint32_t GetDiameter(){
                return m_len;
            }

        private:
            uint32_t m_len;
            uint32_t m_openSpot;
            PartyId* m_ids;

        friend class GraphIterator;
    };

    typedef enum _eThcMsgType {
        THC_MSG_NONE = 0,
        THC_MSG_COLLECTION,
        THC_MSG_CONSISTENCY
    } eThcMsgType;


public:
    BlackBoxExecuter() : m_fIsInitialized(false),
                         m_fIsSecretSet(false),
                         m_fAbort(false), 
                         m_numOfVertices(0),
                         m_numOfNeighbors(0),                         
                         m_ctrRound(0),
                         m_ctrNeighbor(0),
                         m_pGraph(NULL)                                            

    {
        memset(m_s, 0, sizeof(m_s));            
    }

    ~BlackBoxExecuter()
    {
        memset(m_s, 0, sizeof(m_s));
        if(NULL != m_pGraph){
            delete m_pGraph;
        }        
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

        return m_fIsInitialized = true;
    }
    
    bool IsSecretSet() const {
        return m_fIsSecretSet;    
    }

    bool IsReady() const {
        return m_fIsInitialized && m_fIsSecretSet;
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

        if(!generateCollectionMessage(B_out, B_out_size)){
            ocall_print("BlackBoxExecuter::GenerateFirstMessage - Failed to generate collection message");
            return false;
        }

        m_ctrRound++;

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

        if(CIPHERTEXT_SIZE_OF(THC_PLAIN_MSG_SIZE_BYTES) != B_in_size){
            ocall_print("BlackBoxExecuter::Execute - wrong input buffer size, %d", B_in_size);
            return false;
        }
        
        //We should know all graph ids in d (=diameter) rounds, and d < N (=m_numOfVertices)
        if((m_pGraph->GetLength() < m_numOfVertices) && (m_ctrRound > m_numOfVertices)){
            ocall_print("m_ctrRound > m_numOfVertices, yet graph is incomlete");
            return false;
        }

        uint8_t decrypted[THC_PLAIN_MSG_SIZE_BYTES];
        uint8_t* decryptedPtr = decrypted;
        size_t decryptedLen = THC_PLAIN_MSG_SIZE_BYTES;

        sgx_status_t status = decrypt(decrypted, sizeof(decrypted), B_in, m_s);

        if(SGX_SUCCESS != status){
            ocall_print("failed to decrypt B_in, status is %d", status);
            return false; 
        }

        eThcMsgType type;
        uint32_t roundNumber;
        PartyId pid;        

        if(!extractMsgType(&decryptedPtr, &decryptedLen, type)) return false;        
        if(!extractRoundNumber(&decryptedPtr, &decryptedLen, roundNumber)) return false; //TODO - check round number
        if(!extractPartyId(&decryptedPtr, &decryptedLen, pid)) return false; //TODO - check party ID

        m_ctrNeighbor++;

        //This means we are in the graph collection phase
        if(THC_MSG_COLLECTION == type && m_ctrRound <= m_numOfVertices) { 
            
            Graph graph;
            if(!extractGraph(&decryptedPtr, &decryptedLen, graph)) {
                ocall_print("BlackBoxExecuter::Execute - failed to extract graph");
                return false;
            }                

            if(!updateGraph(graph)){
                ocall_print("failed to update graph");
                return false;
            }

        } else if (THC_MSG_CONSISTENCY == type) {
        //This means we are in the consistency checking phase

            if(!extractAbort(&decryptedPtr, &decryptedLen)){
                ocall_print("BlackBoxExecuter::Execute - failed to extract abort");
                return false;
            }

        } else {
            ocall_print("BlackBoxExecuter::parseMessage - invalid message type");
            return false;
        }

        //This means we just recieved a message from the last neighbor of this round
        if(m_ctrNeighbor == m_numOfNeighbors){
            if(!generateOutput(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::Execute - Failed to generate output");
                return false;
            }

            //When we recieve a message from the last neighbor we finish the round
            m_ctrRound++;
            m_ctrNeighbor = 0;
        }
        
        return true;
    }

    void Print(){

        ocall_print("secret key is:");
        print_buffer(m_s, SECRET_KEY_SIZE_BYTES);
        ocall_print(m_fIsInitialized ? "m_fIsInitialized = true" : "m_fIsInitialized = false");
        ocall_print(m_fIsSecretSet ? "m_fIsSecretSet = true" : "m_fIsSecretSet = false");
        ocall_print(m_fAbort ? "m_fAbort = true" : "m_fAbort = false");
        ocall_print("local id is:");
        m_localId.Print();
        ocall_print("m_numOfVertices = %d", m_numOfNeighbors);
        ocall_print("Graph is:");
        if(NULL != m_pGraph){
            m_pGraph->Print();
        } else{
            ocall_print("Graph is NULL");
        }        
        ocall_print("m_numOfNeighbors = %d", m_numOfNeighbors);
        ocall_print("m_ctrRound = %d", m_ctrRound);
        ocall_print("m_ctrNeighbor = %d", m_ctrNeighbor);
        ocall_print("======================");
    }

private:

    bool generateOutput(uint8_t* B_out, size_t B_out_size){

         if(!IsReady()){
            ocall_print("BlackBoxExecuter::generateOutput - not ready");
            return false;
         }

        //This means we are in the last round of consistency checking
        if(m_ctrRound == m_numOfVertices + m_numOfVertices*m_pGraph->GetDiameter()){

            //TODO: check if should abort.

            if(!calculateResult(B_out, B_out_size)){
                ocall_print("BlackBoxExeuter::generateOutput - failed to calculate result");
                return false;
            }

        } else if(m_ctrRound < m_pGraph->GetDiameter()) { 
        //This means we are in the graph collection phase

            if(!generateCollectionMessage(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::generateOutput - failed to generate collection message");
                return false;
            }

        } else {
        //This means we are in the consistency checking phase

            if(!generateConsistencyMessage(B_out, B_out_size)){
                ocall_print("BlackBoxExecuter::generateOutput - failed to generate consistency message");
                return false;
            }
        }

        return true;
    }

    bool updateGraph(Graph& graph){

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::updateGraph - not ready");
            return false;
        }

        GraphIterator iter;
        PartyId pid;

        if(!graph.GetIterator(iter)){
            ocall_print("BlackBoxExecuter::UpdateGraph - failed to get iterator for graph in message");
            return false;
        }

        while(iter.GetNext(pid)){
            if(!m_pGraph->Contains(pid)){
                m_pGraph->AddVertex(pid);
            }
        }

        return true;
    }

    bool calculateResult(uint8_t* B_out, size_t B_out_size)
    {

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::calculateResult - not ready");
            return false;
        }

        ocall_print("Calculating result...");
        //TODO - actual value we want to calculate based on the graph
        return false;
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

        if(bufferLength < sizeof(m_fAbort)){
            ocall_print("BlackBoxExecuter::generateThcMessage - buffer too small to serialize msg type");
            return false;
        }
        
        //Serialize m_fAbort (4B)
        memcpy(bufferPtr, &m_fAbort, sizeof(m_fAbort));

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

    bool extractMsgType(uint8_t** msg, size_t* len, eThcMsgType& type) {

        if(*len < sizeof(eThcMsgType)){
            ocall_print("BlackBoxExecuter::extractMsgType failed, buffer too short, %d", *len);
            return false;
        }

        memcpy(&type, *msg, sizeof(eThcMsgType));
        *msg += sizeof(eThcMsgType);
        *len -= sizeof(eThcMsgType);

        if(THC_MSG_COLLECTION != type && THC_MSG_CONSISTENCY != type){
            ocall_print("BlackBoxExecuter::extractMsgType - invalid message type");
            return false;
        }

        return true;

    }

    bool extractRoundNumber(uint8_t** msg, size_t* len, uint32_t& roundNumber) {

        if(*len < sizeof(uint32_t)){
            ocall_print("BlackBoxExecuter::extractRoundNumber failed, buffer too short, %d", *len);
            return false;
        }

        memcpy(&roundNumber, *msg, sizeof(uint32_t));
        *msg += sizeof(uint32_t);
        *len -= sizeof(uint32_t);

        if(THC_MAX_NUMBER_OF_ROUNDS < roundNumber){
            ocall_print("BlackBoxExecuter::extractRoundNumber failed, invalid round number %d", roundNumber);
            return false;
        }

        return true;
    }

    bool extractPartyId(uint8_t** msg, size_t* len, PartyId& pid) {

        if(!pid.FromBuffer(msg, len)){
            ocall_print("BlackBoxExecuter::extractPartyId failed");
            return false;
        }

        return true;
    }

    bool extractAbort(uint8_t** msg, size_t* len){
        
        if(*len < sizeof(m_fAbort)){
            ocall_print("BlackBoxExecuter::extractAbort failed, buffer too short, %d", *len);
            return false;
        }

        memcpy(&m_fAbort, *msg, sizeof(m_fAbort));
        *msg += sizeof(m_fAbort);
        *len -= sizeof(m_fAbort);

        return true;
    }

    bool extractGraph(uint8_t** msg, size_t* len, Graph& graph){
        if(!graph.FromBuffer(msg, len)) {
            ocall_print("BlackBoxExecuter::extractPartyId failed");
            return false;
        }

        return true;
    }


private:
    uint8_t m_s[SECRET_KEY_SIZE_BYTES];
    bool m_fIsInitialized;
    bool m_fIsSecretSet;
    bool m_fAbort;

    PartyId m_localId;
    uint32_t m_numOfVertices;
    Graph* m_pGraph;
    size_t m_numOfNeighbors;
    uint32_t m_ctrRound;
    uint32_t m_ctrNeighbor;
};


#define MSG_SIZE THC_ENCRYPTED_MSG_SIZE_BYTES
#define MSG(bufPtr, msgNumber) (bufPtr + ((msgNumber)%2)*MSG_SIZE)


int main() {
    BlackBoxExecuter bbx,bbx2,bbx3;
    uint8_t secret[SECRET_KEY_SIZE_BYTES];
    sgx_read_rand(secret, SECRET_KEY_SIZE_BYTES);

   if(!bbx.Initialize(1, 3) ||
      !bbx2.Initialize(2, 3) ||
      !bbx3.Initialize(1, 3)){

       printf("Failed to initialize bbx\n");
       return 1;
   }
   
   if(!bbx.SetSecret(secret, SECRET_KEY_SIZE_BYTES) ||
      !bbx2.SetSecret(secret, SECRET_KEY_SIZE_BYTES) ||
      !bbx3.SetSecret(secret, SECRET_KEY_SIZE_BYTES)) {

       printf("Failed to set bbx secret\n");
       return 1;
   }

   uint8_t bbxMsg[THC_ENCRYPTED_MSG_SIZE_BYTES*2]; uint8_t* ptr1 = bbxMsg;
   uint8_t bbx2Msg[THC_ENCRYPTED_MSG_SIZE_BYTES*2]; uint8_t* ptr2 = bbx2Msg;
   uint8_t bbx3Msg[THC_ENCRYPTED_MSG_SIZE_BYTES*2]; uint8_t* ptr3 = bbx3Msg;

   if(!bbx.GenerateFirstMessage(MSG(ptr1, 0), MSG_SIZE) ||
      !bbx2.GenerateFirstMessage(MSG(ptr2, 0), MSG_SIZE) ||
      !bbx3.GenerateFirstMessage(MSG(ptr3, 0), MSG_SIZE)){

       printf("Failed to GenerateFirstMessage\n");
       return 1;
   }


   for(int i = 0; true; i++){
         if(!bbx.Execute(MSG(ptr2, i), MSG_SIZE, MSG(ptr1, i+1), MSG_SIZE) || 
            !bbx2.Execute(MSG(ptr1, i), MSG_SIZE, MSG(ptr2, i+1), MSG_SIZE) || //should be no output
            !bbx2.Execute(MSG(ptr3, i), MSG_SIZE, MSG(ptr2, i+1), MSG_SIZE) ||
            !bbx3.Execute(MSG(ptr2, i), MSG_SIZE, MSG(ptr3, i+1), MSG_SIZE)){
            printf("bbx.Execute failed\n");
            return -1;
        }

        ocall_print("======bbx:=========");
        bbx.Print();
        ocall_print("======bbx2:=========");
        bbx2.Print();
        ocall_print("======bbx3:=========");
        bbx3.Print();
   }
  

   return 0;
}