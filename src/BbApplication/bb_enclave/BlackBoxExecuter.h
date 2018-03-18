#include "../GeneralSettings.h"
#include "../common_enclave/common_enclave.h"
#include "PartyId.h"
#include "Graph.h"
#include "Edge.h"

class BlackBoxExecuter 
{
    
    typedef enum _eThcMsgType {
        THC_MSG_NONE = 0,
        THC_MSG_COLLECTION,
        THC_MSG_CONSISTENCY
    } eThcMsgType;


public:
    BlackBoxExecuter();

    ~BlackBoxExecuter();

    bool Initialize(uint32_t numOfNeighbors, uint32_t numOfVertices);
    
    bool IsSecretSet() const;

    bool IsInitialized() const;

    bool IsReady() const;

    bool SetSecret(uint8_t s[SECRET_KEY_SIZE_BYTES], size_t size);

    bool GenerateFirstMessage(uint8_t* B_out, size_t B_out_size);

    bool processAbort(uint8_t* B_out, size_t B_out_size);

    /*Called upon dequeue from incoming message queue. B_in is the encrypted payload from a neighbor, B_out is 
        1. Last neighbor in last round of consistency checking - the result of the calculated function or abort.
        2. Last neighbor in other rounds - the encrypted payload to send to the neighbors in the next round.
        3. Otherwise - NULL*/

    bool Execute(uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size);

    bool incrementRound(uint8_t* B_out, size_t B_out_size);

    void Print();

    bool CompareGraph(BlackBoxExecuter& other);

private:

    bool generateOutput(uint8_t* B_out, size_t B_out_size);

    bool updateGraph(Graph& graph);

    bool outputAbort(uint8_t* B_out, size_t B_out_size);

    bool outputResult(uint8_t* B_out, size_t B_out_size);

    bool calculateResult(uint8_t* B_out, size_t B_out_size);

    bool generateThcMessage(uint8_t** buffer, size_t* len, eThcMsgType msgType);

    bool generateConsistencyMessage (uint8_t* B_out, size_t B_out_size);
    /*
    
    MsgType(4B),RoundNumber(4B),LocalId(16B),Graph{Length(4B), Length*16B}, Padding(N-Length * 16B)

    */

    bool generateCollectionMessage (uint8_t* B_out, size_t B_out_size);

    bool extractAndVerityMsgType(uint8_t** msg, size_t* len, eThcMsgType& type);
    bool consumeRoundNumber(uint8_t** msg, size_t* len);
    bool consumePartyId(uint8_t** msg, size_t* len);

    bool consumeAbort(uint8_t** msg, size_t* len);
    bool consumeGraph(uint8_t** msg, size_t* len);

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
