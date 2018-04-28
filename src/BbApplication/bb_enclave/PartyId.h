#include <GeneralSettings.h>
#include <common_enclave.h>
#include <map>
#include <queue>
#include <set>

#ifndef PARTY_ID_H
#define PARTY_ID_H
class PartyId 
{ 
    public: 
        
        PartyId();

        PartyId(char c);

        bool FromBuffer(uint8_t** buffer, size_t* len);

        bool ToBuffer(uint8_t** buffer, size_t* len);

        PartyId& operator=(const PartyId& rhs);

        bool operator< (const PartyId& rhs);

        bool operator<= (const PartyId& rhs);

        bool operator==(const PartyId& other);

        bool operator!=(const PartyId& other);

        void Print();

        bool isValid();

        bool AddNeighbor(PartyId* neighbor);

        bool GetNeighbors(std::queue<PartyId*>& o_queue, std::map<PartyId*,PartyId*>& backtrace);

        bool Matches(PartyId* other);
        
        bool GetEmail(uint8_t** buffer, size_t* len);

    private:
        bool serdes(uint8_t** id, size_t* len, bool fSer);

    private:
        uint8_t m_id[PARTY_ID_SIZE_BYTES];
        PARAM_T m_params[APP_NUM_OF_PARAMETERS];
        char m_email[MAX_EMAIL_SIZE_BYTES];
        std::set<PartyId*> m_neighbors;
};

class VertexIterator
{
    public:
        VertexIterator();

        bool GetNext(PartyId& next);

        void SetVertices(PartyId* vertices);
        void SetLast(uint32_t last);

    private:
        PartyId* m_vertices;
        uint32_t m_current;
        uint32_t m_last;        
};
#endif //PARTY_ID_H