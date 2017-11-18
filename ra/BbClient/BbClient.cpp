#include "BbClient.h"


BbClient::BbClient(Enclave* pEnclave) : m_pEnclave(pEnclave), m_pClient(NULL) {
    
    m_pClient = new AttestationClient(m_pEnclave, m_report);
}

BbClient::~BbClient(){
    delete m_pClient;
}

bool BbClient::obtainCertificate(){
    if(m_report.isValid())
    {
         Log("BbClient::obtainCertificate - already has a valid certificate");
         return true;
    }
    if(readCertificateFromMemory())
    {
        Log("BbClient::obtainCertificate - certificate read from memory successfully");
        return true;
    }
    m_pClient->init();
    m_pClient->start();
    return m_report.isValid();
}

bool BbClient::readCertificateFromMemory(){
    Log("BbClient::readCertificateFromMemory - not implemented");
    return false;
}

bool BbClient::generatePkRequest(Messages::PkRequest pkRequest){
    Log("BbClient::generatePkRequest - not implemented");
    return false;
}


bool BbClient::processPkResponse(Messages::PkResponse pkResponse, Messages::GetSecretRequest getSecretRequest){                    
    Log("BbClient::processPkResponse - not implemented");
    return false;
} 


bool BbClient::processGetSecretResponse(Messages::GetSecretResponse getSecretResponse){
    Log("BbClient::processGetSecretResponse - not implemented");
    return false;
}