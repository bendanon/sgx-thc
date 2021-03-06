#include "../BbApplication/bb_enclave/Graph.h"
#include <iostream>

void ocall_print(const char* format, uint32_t number){
    char output[500];
    memset(output,0,500);
    snprintf(output, 500, format, number);
    std::cout << output << "\n";
}

void ocall_print(const char* format){
    std::cout << format << "\n";
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


int main(){
    Graph graph(10);

    PartyId source(10, 1);
    PartyId mid1(1, 0);
    PartyId mid2(2, 0);

    PartyId mid3(3, 0);
    PartyId mid4(4, 0);
    PartyId mid5(5, 0);
    PartyId mid6(6, 0);
    PartyId mid7(7, 0);
    PartyId mid8(8, 0);
    
    PartyId sink(9, 1);

    std::vector<PartyId*> path;

    graph.AddVertex(source);
    graph.AddVertex(mid1);
    graph.AddVertex(mid2);
    graph.AddVertex(mid3);
    graph.AddVertex(mid4);
    graph.AddVertex(mid5);
    graph.AddVertex(mid6);
    graph.AddVertex(mid7);
    graph.AddVertex(mid8);
    graph.AddVertex(sink);

    graph.AddEdge(source, mid1);
    graph.AddEdge(source, mid2);

    graph.AddEdge(mid1, mid3);
    graph.AddEdge(mid1, mid4);
    graph.AddEdge(mid2, mid5);
    graph.AddEdge(mid2, mid6);

    graph.AddEdge(mid5, mid7);
    graph.AddEdge(mid5, mid8);

    graph.AddEdge(mid7, sink);

    if(!graph.FindClosestMatch(source, path)){
        printf("no match found\n");
        return 0;
    }

    for(PartyId* n : path) {
        n->Print();
    }

    return 0;
}