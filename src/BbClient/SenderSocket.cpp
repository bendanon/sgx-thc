
#include "SenderSocket.h"


SenderSocket::SenderSocket() : m_socket(m_ioService) {

}

SenderSocket::~SenderSocket(){
    
}

bool SenderSocket::serializeBbMessage(uint8_t* inbuf, size_t inbuf_size, vector<std::string>& o_msg){
    
    Messages::BbMSG msg;
    
    msg.set_type(THC_BB_MSG);
    
    for (int i = 0; i < inbuf_size; i++)
        msg.add_bb_msg(inbuf[i]);
    
    string s;    
    if(!msg.SerializeToString(&s)){
        Log("SenderSocket::serializeBbMessage - failed to serialize the BB msg");
        return false;
    }

    o_msg.push_back(to_string(THC_BB_MSG));
    o_msg.push_back(s);

    return true;
}

bool SenderSocket::Send(uint8_t* buffer, size_t bufferLen){

    vector<std::string> v;
    if(!serializeBbMessage(buffer, bufferLen, v)){
        Log("BbClient::runThcProtocol - failed to serializeBbMessage");
        return false;
    }

    string type = v[0];
    string msg = v[1];

    if (msg.size() > 0) {
        const char *msg_c = msg.c_str();
        int msg_length = msg.size();

        string header = to_string(msg_length) + "@" + type + m_host + ":" + std::to_string(m_port);

        char buffer_header[THC_MSG_HEADER_SIZE];
        memset(buffer_header, '\0', THC_MSG_HEADER_SIZE);
        memcpy(buffer_header, header.c_str(), header.length());

        boost::asio::write(m_socket, boost::asio::buffer(buffer_header, THC_MSG_HEADER_SIZE));

        char *buffer_msg = (char*) malloc(sizeof(char) * msg_length);

        memset(buffer_msg, '\0', sizeof(char) * msg_length);
        memcpy(buffer_msg, msg_c, msg_length);

        boost::asio::write(m_socket, boost::asio::buffer(buffer_msg, msg_length));

        free(buffer_msg);

    } else {
        this->close();
    }
}

void SenderSocket::close() {

    boost::system::error_code ec;

    m_socket.lowest_layer().cancel();

    if (ec) {
        Log("Socket shutdown error: %s", ec.message());
    } else {
        m_socket.lowest_layer().close();
    }
}

bool SenderSocket::Init(std::string host, int port){

    m_host = host;
    m_port = port;

    boost::asio::ip::tcp::resolver resolver(m_ioService);
    boost::asio::ip::tcp::resolver::query query(host, std::to_string(port).c_str());
    boost::asio::ip::tcp::resolver::iterator ei = resolver.resolve(query);   

    Log("SenderSocket::Init - Start connecting...");

    boost::system::error_code ec;
    boost::asio::connect(m_socket.lowest_layer(), ei, ec);

    while (ec) {
        Log("SenderSocket::Init - waiting.....");
        boost::this_thread::sleep_for(boost::chrono::seconds{2});
        boost::asio::connect(m_socket.lowest_layer(), ei, ec);
    }

    return true;
}
