#ifndef BLACK_BOX_EXECUTER_H
#define BLACK_BOX_EXECUTER_H

#include "../../th_definitions.h"

using namespace std;

class BlackBoxExecuter 
{
public:
    BlackBoxExecuter();
    ~BlackBoxExecuter();
    
    bool IsInitialized();

    bool Init(uint8_t s[SECRET_KEY_SIZE_BYTES], size_t s_size);

    bool Execute(uint8_t B_in[B_IN_SIZE_BYTES], size_t B_in_size, 
                         uint8_t B_out[B_OUT_SIZE_BYTES], size_t B_out_size);    

private:
    uint8_t m_s[SECRET_KEY_SIZE_BYTES];
    bool m_IsInitialized;
};

#endif //BLACK_BOX_EXECUTER_H
