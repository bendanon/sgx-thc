#ifndef ADJ_MATRIX_H
#define ADJ_MATRIX_H

#include "../../th_definitions.h"

class AdjacencyMatrix
{

public:

    AdjacencyMatrix(uint32_t n);
    ~AdjacencyMatrix();
    bool connect(uint32_t origin, uint32_t destin);
    bool toBuffer(uint32_t* buffer, uint32_t bufsize);
    bool fromBuffer(uint32_t* buffer, uint32_t bufsize);

private:
    uint32_t n;
    uint32_t *adj;
};
#endif