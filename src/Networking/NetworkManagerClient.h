#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include "NetworkManager.h"

class NetworkManagerClient : public NetworkManager {

public:
    NetworkManagerClient(int port, std::string host = "localhost");
    void Init();
    void connectCallbackHandler(CallbackHandler cb);
    void startService();
    void setHost(std::string host);
    bool SendMsg(vector<string> msg);

private:
    

private:
    std::string host;
    Client *client = NULL;
};

#endif //NETWORK_MANAGER_H


