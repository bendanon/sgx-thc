#include "SkgServer.h"


SkgServer::SkgServer(Enclave* pEnclave) : m_pEnclave(pEnclave), m_pClient(NULL) {
    
    m_pClient = new AttestationClient(m_pEnclave, m_report);
}

SkgServer::~SkgServer(){
    delete m_pClient;
}

bool SkgServer::obtainCertificate(){
    if(m_report.isValid())
    {
         Log("SkgServer::obtainCertificate - already has a valid certificate");
         return true;
    }
    if(readCertificateFromMemory())
    {
        Log("SkgServer::obtainCertificate - certificate read from memory successfully");
        return true;
    }
    m_pClient->init();
    m_pClient->start();
    return m_report.isValid();
}

bool SkgServer::readCertificateFromMemory(){
    Log("SkgServer::readCertificateFromMemory - not implemented");
    return false;
}

bool SkgServer::processPkRequest(Messages::PkRequest pkRequest, Messages::PkResponse pkResponse){                    
    Log("SkgServer::processPkRequest - not implemented");
    return false;
} 

bool SkgServer::processGetSecretRequest(Messages::GetSecretRequest getSecretRequest, Messages::GetSecretResponse getSecretResponse){
    Log("SkgServer::processGetSecretRequest - not implemented");
    return false;
}