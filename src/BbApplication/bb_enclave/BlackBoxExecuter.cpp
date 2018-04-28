#include "BlackBoxExecuter.h"
#include <vector>

BlackBoxExecuter::BlackBoxExecuter() : m_fIsInitialized(false),
                        m_fIsSecretSet(false),
                        m_abortedRound(MAX_UINT32), 
                        m_numOfVertices(0),
                        m_numOfNeighbors(0),                         
                        m_ctrRound(0),
                        m_abortCounter(0),
                        //m_ctrNeighbor(0),
                        m_pGraph(NULL),
                        m_pNeighbors(NULL),
                        m_pRoundChecklist(NULL),
                        m_decrypted(NULL),
                        m_decryptedSize(0),
                        m_encryptedSize(0)


{
    memset(m_s, 0, sizeof(m_s));            
}

BlackBoxExecuter::~BlackBoxExecuter()
{
    memset(m_s, 0, sizeof(m_s));
    delete m_pGraph;
    delete m_pNeighbors;
    delete m_pRoundChecklist;
    delete m_decrypted;
}

bool BlackBoxExecuter::Initialize(bb_config_t* p_config) 
{
    uint8_t localPartyBuf[APP_PARTY_FULL_SIZE_BYTES];
    size_t localPartySize = APP_PARTY_FULL_SIZE_BYTES;
    uint8_t* bufPtr = localPartyBuf;
        
    if(p_config->num_of_neighbors > p_config->num_of_vertices){
        ocall_print("BlackBoxExecuter::Initialize - numOfNeighbors > numOfVertices");
        return false;
    }

    if(MAX_GRAPH_SIZE < p_config->num_of_vertices){
        ocall_print("BlackBoxExecuter::Initialize - MAX_GRAPH_SIZE < numOfVertices");
        return false;
    }

    //Use SGX hardware randomness to generate a local ID string
    sgx_status_t status = sgx_read_rand((unsigned char*)bufPtr, PARTY_ID_SIZE_BYTES);        
    
    if(status) {
        ocall_print("BlackBoxExecuter::Initialize - sgx_read_rand status is %d\n", status);
        return false;
    }

    memcpy(bufPtr + PARTY_ID_SIZE_BYTES, p_config->params, APP_PARTY_PARAMS_SIZE_BYTES);

    memcpy(bufPtr + PARTY_ID_SIZE_BYTES + APP_PARTY_PARAMS_SIZE_BYTES, p_config->email, MAX_EMAIL_SIZE_BYTES);

    if(!m_localId.FromBuffer(&bufPtr, &localPartySize)) {
        ocall_print("BlackBoxExecuter::Initialize -failed to parse id from buffer");
        return false;
    }
    
    m_localId.Print();

    m_numOfVertices = p_config->num_of_vertices;
    m_numOfNeighbors = p_config->num_of_neighbors;

    m_pGraph = new Graph(m_numOfVertices);

    m_pGraph->AddVertex(m_localId);

    #if 0
    //+1 because we also store the local is in the neighbors graph
    m_pNeighbors = new Graph(m_numOfNeighbors + 1);

    if(NULL == m_pNeighbors){
        ocall_print("BlackBoxExecuter::Initialize - failed to allocate m_pNeighbors");
        return false;
    }
    #endif

    m_pGraph->AddVertex(m_localId);

    m_pRoundChecklist = new Graph(m_numOfNeighbors);

    if(NULL == m_pRoundChecklist){
        ocall_print("BlackBoxExecuter::Initialize - failed to allocate m_pRoundChecklist");
        return false;
    }

    m_decryptedSize = THC_PLAIN_MSG_SIZE_BYTES(m_numOfVertices);
    m_encryptedSize = THC_ENCRYPTED_MSG_SIZE_BYTES(m_numOfVertices);

    m_decrypted = new uint8_t[m_decryptedSize];

    if(NULL == m_decrypted){
        ocall_print("BlackBoxExecuter::Initialize - failed to allocate m_decrypted");
        return false;
    }

    return m_fIsInitialized = true;
}

bool BlackBoxExecuter::IsSecretSet() const {
    return m_fIsSecretSet;    
}

bool BlackBoxExecuter::IsInitialized() const {
    return m_fIsInitialized;
}

bool BlackBoxExecuter::IsReady() const {
    return IsInitialized() && IsSecretSet();
}

bool BlackBoxExecuter::SetSecret(uint8_t s[SECRET_KEY_SIZE_BYTES], size_t size)
{
    if(SECRET_KEY_SIZE_BYTES != size) {
        ocall_print("BlackBoxExecuter::SetSecret - secret size different from expected, %d", size);
        return false;
    }

    memcpy(m_s, s, SECRET_KEY_SIZE_BYTES);
    
    return m_fIsSecretSet = true;
}

bool BlackBoxExecuter::GenerateFirstMessage(uint8_t* B_out, size_t B_out_size){

    if(m_encryptedSize != B_out_size){
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

bool BlackBoxExecuter::processAbort(uint8_t* B_out, size_t B_out_size){
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

bool BlackBoxExecuter::Execute(uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size)
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

    if(m_encryptedSize != B_in_size){
        ocall_print("BlackBoxExecuter::Execute - wrong input buffer size, %d", B_in_size);
        return false;
    }
    
    //We should know all graph vertices in d (=diameter) rounds, and d < N (=m_numOfVertices)
    #ifndef SCHIZZO_TEST
    if((m_pGraph->GetSize() < m_numOfVertices) && (m_ctrRound > m_numOfVertices)){
        ocall_print("m_ctrRound > m_numOfVertices, yet graph is incomlete");
        return false;
    }
    #endif

    uint8_t* decryptedPtr = m_decrypted;
    size_t decryptedLen = m_decryptedSize;

    sgx_status_t status = decrypt(m_decrypted, m_decryptedSize, B_in, m_s);

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

bool BlackBoxExecuter::incrementRound(uint8_t* B_out, size_t B_out_size){

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

void BlackBoxExecuter::Print(){

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

bool BlackBoxExecuter::CompareGraph(BlackBoxExecuter& other){
    return m_pGraph->IsEquivalent(other.m_pGraph);
}

bool BlackBoxExecuter::generateOutput(uint8_t* B_out, size_t B_out_size){

    if(!IsReady()){
        ocall_print("BlackBoxExecuter::generateOutput - not ready");
        return false;
    }

    //This means we are in the last round of consistency checking
    if(m_ctrRound >= m_numOfVertices + m_numOfVertices*m_pGraph->GetDiameter()){

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

bool BlackBoxExecuter::updateGraph(Graph& graph){

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
    while(vi.GetNext(pid)) {
        if(!m_pGraph->AddVertex(pid)){
            ocall_print("BlackBoxExecuter::updateGraph - failed to insert vertex");
            return false;
        }
    }

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

bool BlackBoxExecuter::outputAbort(uint8_t* B_out, size_t B_out_size){
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

bool BlackBoxExecuter::outputResult(uint8_t* B_out, size_t B_out_size){
    
    if(sizeof(RESULT_CANARY) > B_out_size){
        ocall_print("BlackBoxExecuter::calculateResult - B_out_size smaller than result message, %d", B_out_size);
        return false;
    }
    if(sizeof(RESULT_CANARY)-1 != snprintf((char*)B_out, sizeof(RESULT_CANARY), "%s", RESULT_CANARY)){
        ocall_print("BlackBoxExecuter::calculateResult - failed to print result message");
        return false;
    }

    B_out += strlen(RESULT_CANARY);
    B_out_size -= strlen(RESULT_CANARY);
    
    std::vector<PartyId*> path;

    if(!m_pGraph->FindClosestMatch(m_localId, path)){
        if(sizeof(NO_MATCH_STRING) > B_out_size){
            ocall_print("BlackBoxExecuter::calculateResult - B_out_size smaller than result message, %d", B_out_size);
            return false;
        }
        if(sizeof(NO_MATCH_STRING)-1 != snprintf((char*)B_out, sizeof(NO_MATCH_STRING)+1, "%s", NO_MATCH_STRING)){
            ocall_print("BlackBoxExecuter::calculateResult - failed to print result message");
            return false;
        }

        return true;
    }
    
    uint8_t* outPtr = B_out;
    for(PartyId* p : path){

        if(!p->GetEmail(&outPtr, &B_out_size)){
            ocall_print("BlackBoxExecuter::outputResult - GetEmail failed");
            return false;
        }

        memcpy(outPtr, REAULT_EMAIL_DELIMITER, strlen(REAULT_EMAIL_DELIMITER));        
        outPtr += strlen(REAULT_EMAIL_DELIMITER);
    }

    return true;
}

bool BlackBoxExecuter::calculateResult(uint8_t* B_out, size_t B_out_size)
{
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

bool BlackBoxExecuter::generateThcMessage(uint8_t** buffer, size_t* len, eThcMsgType msgType){

    if(!IsReady()){
        ocall_print("BlackBoxExecuter::generateThcMessage - not ready");
        return false;
    }

    if(m_decryptedSize != *len){
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

bool BlackBoxExecuter::generateConsistencyMessage (uint8_t* B_out, size_t B_out_size){

    if(!IsReady()){
        ocall_print("BlackBoxExecuter::generateConsistencyMessage - not ready");
        return false;
    }

    if(m_encryptedSize != B_out_size){
        ocall_print("BlackBoxExecuter::generateConsistencyMessage - wrong buffer size, %d", B_out_size);
        return false;
    }

    uint8_t* bufferPtr = m_decrypted;
    size_t bufferLength = m_decryptedSize;

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
    if(SGX_SUCCESS != (status = encrypt(m_decrypted, m_decryptedSize, B_out, m_s))){
        ocall_print("BlackBoxExecuter::generateConsistencyMessage - failed to encrypt collection message, %d", status);
        return false;
    }

    return true;
}

/*

MsgType(4B),RoundNumber(4B),LocalId(16B),Graph{Length(4B), Length*16B}, Padding(N-Length * 16B)

*/

bool BlackBoxExecuter::generateCollectionMessage (uint8_t* B_out, size_t B_out_size){

    if(!IsReady()){
        ocall_print("BlackBoxExecuter::generateCollectionMessage - not ready");
        return false;
    }

    if(m_encryptedSize != B_out_size){
        ocall_print("BlackBoxExecuter::generateCollectionMessage - wrong buffer size, %d", B_out_size);
        return false;
    }

    uint8_t* bufferPtr = m_decrypted;
    size_t bufferLength = m_decryptedSize;

    if(!generateThcMessage(&bufferPtr, &bufferLength, THC_MSG_COLLECTION)){
        ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to generate message");
        return false;
    }

    if(!m_pGraph->ToBuffer(&bufferPtr, &bufferLength)){
        ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to serialize graph");
        return false;
    }

    sgx_status_t status;
    if(SGX_SUCCESS != (status = encrypt(m_decrypted, m_decryptedSize, B_out, m_s))){
        ocall_print("BlackBoxExecuter::generateCollectionMessage - failed to encrypt collection message, %d", status);
        return false;
    }

    return true;
}

bool BlackBoxExecuter::extractAndVerityMsgType(uint8_t** msg, size_t* len, eThcMsgType& type) {

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

bool BlackBoxExecuter::consumeRoundNumber(uint8_t** msg, size_t* len) {
    
    uint32_t roundNumber;
    if(*len < sizeof(uint32_t)){
        ocall_print("BlackBoxExecuter::consumeRoundNumber failed, buffer too short, %d", *len);
        return false;
    }

    memcpy(&roundNumber, *msg, sizeof(uint32_t));
    *msg += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    if(THC_MAX_NUMBER_OF_ROUNDS(m_numOfVertices) < roundNumber){
        ocall_print("BlackBoxExecuter::consumeRoundNumber failed, invalid round number %d", roundNumber);
        return false;
    }

    if(roundNumber != m_ctrRound){
        ocall_print("BlackBoxExecuter::consumeRoundNumber - received a message with the wrong round number %d", roundNumber);
        return false;
    }

    return true;
}

bool BlackBoxExecuter::consumePartyId(uint8_t** msg, size_t* len) {

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

    if(!m_pGraph->AddVertex(neighborId)){
        ocall_print("BlackBoxExecuter::consumePartyId - failed to add vertex for neighbor");
        return false;
    }

    if(!m_pGraph->AddEdge(m_localId, neighborId)){
        ocall_print("BlackBoxExecuter::consumePartyId - failed to add edge to neighbor");
        return false;
    }

    #if 0
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
    #endif

    if(!m_pRoundChecklist->AddVertex(neighborId)){
        ocall_print("BlackBoxExecuter::consumePartyId - failed to add vertex for neighbor to checklist");
        return false;
    }

    return true;
}

bool BlackBoxExecuter::consumeAbort(uint8_t** msg, size_t* len){
    
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

bool BlackBoxExecuter::consumeGraph(uint8_t** msg, size_t* len){
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