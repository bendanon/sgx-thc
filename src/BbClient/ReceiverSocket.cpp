#include "ReceiverSocket.h"

ReceiverSocket::ReceiverSocket() : m_socket(m_ioService), m_encrypted(NULL), m_encryptedSize(0) {

}

ReceiverSocket::~ReceiverSocket(){
    delete m_encrypted;
}

boost::asio::ip::tcp::socket& ReceiverSocket::socket(){
    return m_socket;
}


bool ReceiverSocket::Init(Queues* p_queues, size_t numOfVertices){
    m_queues = p_queues;

    if(MAX_GRAPH_SIZE < numOfVertices){
        Log("ReceiverSocket::Init - invalid numOfVertices (%d)", numOfVertices);
        return false;
    }
    m_encryptedSize = THC_ENCRYPTED_MSG_SIZE_BYTES(numOfVertices);

    m_encrypted = new uint8_t[m_encryptedSize];
    if(NULL == m_encrypted){
        Log("ReceiverSocket::Init - failed to allocate encrypted buffer");
        return false;   
    }

    return true;
}

void ReceiverSocket::Receive(){
    
    //Log("ReceiverSocket::Receive - started=====================================================");  
    std::string msg;
    uint32_t port;
    std::string ip = m_socket.remote_endpoint().address().to_string();

    while(read(port, msg)){        
        //Log("ReceiverSocket::Receive - Received message from %s, %d", ip, port);

        while(!m_queues->InsertFromNeighbor(ip, port, msg)){
            //Log("ReceiverSocket::Receive - failed to insert from %s, %d, retrying...", ip, port);                        
            boost::this_thread::sleep_for(boost::chrono::milliseconds{1});            
        }

        msg = "";
    }

    //Log("ReceiverSocket::Receive - stopped=====================================================", log::error);  
}

bool ReceiverSocket::read(uint32_t& port, std::string& msg){
    char buffer_header[THC_MSG_HEADER_SIZE];
    memset(buffer_header, '\0', THC_MSG_HEADER_SIZE);
    
    int msg_size = 0;
    int type = 0;
    char *buffer = NULL;

    boost::system::error_code ec;
    int read = boost::asio::read(m_socket, boost::asio::buffer(buffer_header, THC_MSG_HEADER_SIZE), ec);

    if (ec) {

        if ((boost::asio::error::eof == ec) || (boost::asio::error::connection_reset == ec)) {
            //Log("Connection has been closed by remote host");
        } else {
            Log("Unknown socket error while reading occured!", log::error);
        }

        return false;
    }

    vector<string> incoming;
    boost::split(incoming, buffer_header, boost::is_any_of("@"));

    msg_size = boost::lexical_cast<int>(incoming[0]);

    type = boost::lexical_cast<int>(incoming[1]);
    port = boost::lexical_cast<int>(incoming[2]);

    buffer = (char*) malloc(sizeof(char) * msg_size);
    memset(buffer, '\0', sizeof(char)*msg_size);

    read = boost::asio::read(m_socket, boost::asio::buffer(buffer, msg_size), ec);

    if (ec) {

        if ((boost::asio::error::eof == ec) || (boost::asio::error::connection_reset == ec)) {
            //Log("Connection has been closed by remote host");
        } else {
            Log("Unknown socket error while reading occured!", log::error);
        }

        return false;
    }
    
    std::string msgBody(buffer, msg_size);

    Messages::BbMSG in;        
    if (!in.ParseFromString(msgBody) || (in.type() != THC_BB_MSG)){
        Log("ReceiverSocket::read - failed to parse bb message", log::error);
        return false;
    }
    
    for (int i = 0; i < m_encryptedSize; i++)
        m_encrypted[i] = in.bb_msg(i);

    std::string msgBodyDeserialized((const char*)m_encrypted, m_encryptedSize);
    msg += msgBodyDeserialized;

    return true;    
}