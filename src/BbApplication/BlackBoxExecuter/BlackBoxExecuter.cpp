#include "BlackBoxExecuter.h"

BlackBoxExecuter::BlackBoxExecuter() : m_IsInitialized(false)
{
    memset(m_s, 0, sizeof(m_s));
}

bool BlackBoxExecuter::IsInitialized()
{
    return m_IsInitialized;    
}

bool BlackBoxExecuter::Init(uint8_t s[SECRET_KEY_SIZE_BYTES], size_t s_size)
{
    if(s_size != SECRET_KEY_SIZE_BYTES) return false;

    memcpy(m_s, s, SECRET_KEY_SIZE_BYTES);
    m_IsInitialized = true;
    return true;
}

bool BlackBoxExecuter::Execute(uint8_t B_in[B_IN_SIZE_BYTES], size_t B_in_size, 
                                       uint8_t B_out[B_OUT_SIZE_BYTES], size_t B_out_size)
{
    if(B_in_size != B_IN_SIZE_BYTES) return false;
    if(B_out_size != B_OUT_SIZE_BYTES) return false;

    
    for(int i = 0; i < B_IN_SIZE_BYTES; i++)
    {
        B_out[i] = B_in[i] ^ m_s[i % SECRET_KEY_SIZE_BYTES];
    }

    return true;
}

BlackBoxExecuter::~BlackBoxExecuter()
{
    memset(m_s, 0, sizeof(m_s));
}