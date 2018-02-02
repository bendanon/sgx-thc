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
    char output[50];
    memset(output,0,50);
    snprintf(output, 50, format, number);
    ocall_print(output);
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

            bool FromBuffer(uint8_t** id, uint32_t* len){
                return serdes(id, len, false);
            }

            bool ToBuffer(uint8_t** id, uint32_t* len){
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
                char toPrint[PARTY_ID_SIZE_BYTES * 3 + 3];
                char* ptr = toPrint;

                snprintf(ptr++,2, "[");
            
                for(int i = 0; i < PARTY_ID_SIZE_BYTES; i++){
                    snprintf(ptr, 4, "%02X,", (unsigned char)m_id[i]);
                    ptr = ptr + 3;
                }
                
                snprintf(ptr-1, 2, "]");

                ocall_print(toPrint);
            }

            bool isValid(){
                for(int i = 0; i < sizeof(m_id); i++){
                    if(0 != m_id[i]){
                        return true;
                    }
                }
            }

        private:
            bool serdes(uint8_t** id, uint32_t* len, bool fSer){
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
            GraphIterator() : m_ids(NULL), m_current(0), m_len(0) { }

            bool GetNext(PartyId& next){
                if(m_ids == NULL){
                    ocall_print("GraphIterator::GetNext - iterator not initialized");
                    return false;
                }
                if(m_current >= m_len) {
                    ocall_print("GraphIterator::GetNext - no more elements");                    
                    return false;
                }
                next = m_ids[m_current++];
                return true;
            }

            void SetIds(PartyId* ids){ m_ids = ids; }
            void SetLen(uint32_t len){ m_len = len; }

        private:
            PartyId* m_ids;
            uint32_t m_current;
            uint32_t m_len;        
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
                iter.SetLen(m_len);

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
                return m_len;
            }

            bool IsInitialized() const {
                return m_ids != NULL;
            }

            bool FromBuffer(uint8_t** buffer, uint32_t* len) {

                if(IsInitialized()){
                    ocall_print("Graph::FromBuffer - called on initialized graph");
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

            bool ToBuffer(uint8_t** buffer, uint32_t* len) {

                if(!IsInitialized()){
                    ocall_print("Graph::ToBuffer - called on not initialized graph");
                    return false;
                }

                if(*len < sizeof(uint32_t)){
                    ocall_print("Graph::FromBuffer::m_len failed, buffer too short, %d", *len);
                    return false;
                }
                
                memcpy(*buffer, &m_len, sizeof(uint32_t));
                *buffer += sizeof(m_len);
                *len -= sizeof(m_len);

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
                         m_numOfVertices(0),
                         m_numOfNeighbors(0),                                              
                         m_fGraphCollected(false),
                         m_ctrRound(0),
                         m_ctrNeighbor(0)                                             

    {
        memset(m_s, 0, sizeof(m_s));            
    }

    ~BlackBoxExecuter()
    {
        memset(m_s, 0, sizeof(m_s));
        delete m_pGraph;
    }

    bool Initialize(uint32_t numOfNeighbors, uint32_t numOfVertices) 
    {

        uint8_t* localId = new uint8_t[PARTY_ID_SIZE_BYTES];
        uint32_t localIdSize = PARTY_ID_SIZE_BYTES;

        //Use SGX hardware randomness to generate a local ID string
        sgx_status_t status = sgx_read_rand((unsigned char*)localId, localIdSize);        
        
        if(status) {
            ocall_print("BlackBoxExecuter::Initialize - sgx_read_rand status is %d\n", status);
            return false;
        } 

        if(!m_localId.FromBuffer(&localId, &localIdSize)) {
            ocall_print("BlackBoxExecuter::Initialize -failed to parse id from buffer");
            return false;
        }

        delete localId;

        m_numOfVertices = numOfVertices;
        m_numOfNeighbors = numOfNeighbors;

        m_pGraph = new Graph(m_numOfVertices);

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
        uint32_t decryptedLen = THC_PLAIN_MSG_SIZE_BYTES;

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

            //TODO - extract abort
            /*if(!updateAbort(msg)){
                ocall_print("failed to update abort");
                return false;
            }*/

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

        } else if(m_ctrRound <= m_pGraph->GetDiameter()) { 
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

        m_pGraph->Print();      

        return true;
    }

    bool calculateResult(uint8_t* B_out, size_t B_out_size)
    {

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::calculateResult - not ready");
            return false;
        }
        //TODO - actual value we want to calculate based on the graph
        return false;
    }

    bool generateConsistencyMessage (uint8_t* B_out, size_t B_out_size){

        if(!IsReady()){
            ocall_print("BlackBoxExecuter::generateConsistencyMessage - not ready");
            return false;
        }
        //TODO - encrypt a padded true or false
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

        if(THC_PLAIN_MSG_SIZE_BYTES != B_out_size){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - buffer too small, %d", B_out_size);
            return false;
        }

        eThcMsgType msgType = THC_MSG_COLLECTION;

        uint8_t buffer[THC_PLAIN_MSG_SIZE_BYTES];
        uint8_t* bufferPtr = buffer;
        uint32_t bufferLength = THC_PLAIN_MSG_SIZE_BYTES;
        memset(B_out, 0, B_out_size);

        if(B_out_size < sizeof(msgType)){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - buffer too small to serialize msg type");
            return false;
        }
        
        //Serialize msg type (4B)
        memcpy(B_out, &msgType, sizeof(msgType));
        B_out += sizeof(msgType);
        B_out_size -= sizeof(msgType);

        if(B_out_size < sizeof(m_ctrRound)){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - buffer too small to serialize m_ctrRound");
            return false;
        }

        //Serialize the round (4B)        
        memcpy(B_out, &m_ctrRound, sizeof(m_ctrRound));
        B_out += sizeof(m_ctrRound);
        B_out_size -= sizeof(m_ctrRound);

        if(!m_localId.ToBuffer(&bufferPtr, &bufferLength)){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to serialize m_localId");
            return false;
        }

        if(!m_pGraph->ToBuffer(&bufferPtr, &bufferLength)){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to serialize graph");
            return false;
        }

        //Padding to maximum length message
        PartyId zero;
        for(int i = 0; i < m_numOfVertices - m_pGraph->GetLength(); i++){
            if(!zero.ToBuffer(&bufferPtr, &bufferLength)){
                ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to serialize padding");
                return false;
            }
        }

        sgx_status_t status;
        if(SGX_SUCCESS != (status = encrypt(buffer, THC_PLAIN_MSG_SIZE_BYTES,B_out, m_s))){
            ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to encrypt collection message, %d", status);
            return false;
        }

        return true;
    }

    bool extractMsgType(uint8_t** msg, uint32_t* len, eThcMsgType& type) {

        if(*len < sizeof(eThcMsgType)){
            ocall_print("EnclaveMessage::extractMsgType failed, buffer too short, %d", *len);
            return false;
        }

        memcpy(&type, *msg, sizeof(eThcMsgType));
        *msg += sizeof(eThcMsgType);
        *len -= sizeof(eThcMsgType);

        if(THC_MSG_COLLECTION != type && THC_MSG_CONSISTENCY != type){
            ocall_print("EnclaveMessage::extractMsgType - invalid message type");
            return false;
        }

        return true;

    }

    bool extractRoundNumber(uint8_t** msg, uint32_t* len, uint32_t& roundNumber) {

        if(*len < sizeof(uint32_t)){
            ocall_print("EnclaveMessage::extractRoundNumber failed, buffer too short, %d", *len);
            return false;
        }

        memcpy(&roundNumber, *msg, sizeof(uint32_t));
        *msg += sizeof(uint32_t);
        *len -= sizeof(uint32_t);

        if(THC_MAX_NUMBER_OF_ROUNDS < roundNumber){
            ocall_print("EnclaveMessage::extractRoundNumber failed, invalid round number %d", roundNumber);
            return false;
        }

        return true;
    }

    bool extractPartyId(uint8_t** msg, uint32_t* len, PartyId& pid) {

        if(!pid.FromBuffer(msg, len)){
            ocall_print("EnclaveMessage::extractPartyId failed");
            return false;
        }

        return true;
    }

    bool extractGraph(uint8_t** msg, uint32_t* len, Graph& graph){
        if(!graph.FromBuffer(msg, len)) {
            ocall_print("EnclaveMessage::extractPartyId failed");
            return false;
        }

        return true;
    }


private:
    uint8_t m_s[SECRET_KEY_SIZE_BYTES];
    bool m_fIsInitialized;
    bool m_fIsSecretSet;

    PartyId m_localId;
    uint32_t m_numOfVertices;
    Graph* m_pGraph;
    size_t m_numOfNeighbors;
    uint32_t m_ctrRound;
    uint32_t m_ctrNeighbor;
    bool m_fGraphCollected;
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

    //Seal (s) [to MRENCLAVE] and output sealed data.
    status = sgx_seal_data(0, NULL, sizeof(s_decrypted), s_decrypted, sealed_size, p_sealed_s);
    
    if(status) {
        ocall_print("sgx_seal_data status is %d\n", status);
        return status;
    } 

    return SGX_SUCCESS;
}



/*
[Execution: input sealed data (s), memory buffer B_in]
1. Unseal s
2. Execute B_out=X_s(B_in)
3. Output B_out
*/
sgx_status_t bb_exec(sgx_sealed_data_t* p_sealed_s,  size_t sealed_size, //in (Seal(s))
                       uint8_t* B_in, size_t B_in_size,                   //in (B_in)
                       uint8_t* B_out, size_t B_out_size)                 //out (B_out)
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    
    if(!bbx.IsSecretSet())
    {
        //Unseal s
        uint8_t s_unsealed[SECRET_KEY_SIZE_BYTES];
        uint32_t unsealed_text_length = sizeof(s_unsealed);

        status = sgx_unseal_data(p_sealed_s,
                                NULL,
                                0,
                                s_unsealed, 
                                &unsealed_text_length);
                                
        
        if(status) {
            ocall_print("sgx_unseal_data status is %d\n", status);
            return status;
        } 

        bbx.SetSecret(s_unsealed, SECRET_KEY_SIZE_BYTES);
    }

    bool ret = false;

    ret = bbx.Execute(B_in, B_in_size, B_out, B_out_size);

    if(!ret) {
        ocall_print("bbx.Execute failed");
        return status;
    }

    return SGX_SUCCESS;
}

sgx_status_t derive_smk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                        sgx_ec_key_128bit_t* p_smk, size_t smk_size) {

    return _derive_smk(p_pk, pk_size, p_smk,smk_size, &bb_priv_key);

}