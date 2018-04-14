#include "../GeneralSettings.h"
#include "../common_enclave/common_enclave.h"

#ifndef PARTY_ID_H
#define PARTY_ID_H
class PartyId 
{ 
    public: 
        
        PartyId();

        bool FromBuffer(uint8_t** buffer, size_t* len);

        bool ToBuffer(uint8_t** buffer, size_t* len);

        PartyId& operator=(const PartyId& rhs);

        bool operator< (const PartyId& rhs);

        bool operator<= (const PartyId& rhs);

        bool operator==(const PartyId& other);

        bool operator!=(const PartyId& other);

        void Print();

        bool isValid();

    private:
        bool serdes(uint8_t** id, size_t* len, bool fSer);

    private:
        uint8_t m_id[PARTY_ID_SIZE_BYTES];
        PARAM_T m_auxData[APP_NUM_OF_PARAMETERS_SIZE_BYTES];
};

class VertexIterator
{
    public:
        VertexIterator();

        bool GetNext(PartyId& next);

        void SetVertices(PartyId* vertices);
        void SetLast(uint32_t len);

    private:
        PartyId* m_vertices;
        uint32_t m_current;
        uint32_t m_last;        
};
#endif //PARTY_ID_H