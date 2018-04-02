#include "ThcServer.h"

ThcServer::ThcServer(Json::Value& config) : m_config(config), 
                                            m_acceptor(m_ioService, 
                                                       boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 
                                                       m_config["port"].asUInt())) {

    const Json::Value& neighConfig = m_config["neighbors"];

    m_numOfNeighbors = neighConfig.size();

    m_sockets = new ReceiverSocket[m_numOfNeighbors];
    m_threadPtrs = new boost::thread*[m_numOfNeighbors];
}

ThcServer::~ThcServer(){
    delete[] m_sockets;
}

void ThcServer::RunServer(){

    if(NULL == m_queues){
        Log("ThcServer::RunServer - called with m_queues == NULL", log::error);
        return;
    }

    startAccept();
    m_ioService.run();
}

void ThcServer::startAccept(){

    //startAccept will be called by handleAccept once too much, this stops it
    if(m_acceptedConnections >= m_numOfNeighbors){        
        return;
    }

    m_sockets[m_acceptedConnections].Init(m_queues);

    m_acceptor.async_accept(m_sockets[m_acceptedConnections].socket(), 
                                boost::bind(&ThcServer::handleAccept, 
                                            this, 
                                            &m_sockets[m_acceptedConnections], 
                                            boost::asio::placeholders::error));    
}

void ThcServer::handleAccept(ReceiverSocket* receiverSocket, const boost::system::error_code& error){

    Log("Connection from %s", receiverSocket->socket().remote_endpoint().address().to_string());
    m_threadPtrs[m_acceptedConnections++] = new boost::thread(&ReceiverSocket::Receive, receiverSocket);
    startAccept();
}

void ThcServer::SetQueues(Queues* queues){
    m_queues = queues;
}