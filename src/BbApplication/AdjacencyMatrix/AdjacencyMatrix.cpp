#include "AdjacencyMatrix.h"

AdjacencyMatrix::AdjacencyMatrix(uint32_t n) 
{
    this->n = n;
    adj = new uint32_t[n*n];
    memset(adj, 0 , n*n);
}

AdjacencyMatrix::~AdjacencyMatrix()
{
    delete adj;
}

bool AdjacencyMatrix::connect(uint32_t origin, uint32_t destin) 
{
    if( origin > n || destin > n)
    {
        return false;
    }
    else
    {
        ((uint32_t**)adj)[origin - 1][destin - 1] = 1;
    }
}

bool AdjacencyMatrix::toBuffer(uint32_t* buffer, uint32_t bufsize){
    if(bufsize < n*n) {
        return false;
    }
    memcpy(buffer, adj, (uint32_t)n * n);
    return true;
}

bool AdjacencyMatrix::fromBuffer(uint32_t* buffer, uint32_t bufsize){
    if(bufsize < n*n) {
        return false;
    }
    memcpy(adj, buffer, n*n);
    return true;
}
