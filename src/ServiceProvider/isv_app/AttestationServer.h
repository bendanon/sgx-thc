#ifndef AttestationServer_H
#define AttestationServer_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "ServiceProvider.h"
#include "NetworkManagerServer.h"
#include "LogBase.h"
#include "Messages.pb.h"
#include "WebService.h"
#include "../GeneralSettings.h"


using namespace std;

class AttestationServer{

public:
    static AttestationServer* getInstance();
    virtual ~AttestationServer();
    int init();
    vector<string> incomingHandler(string v, int type);
    void start();

private:
    AttestationServer(int port = Settings::rh_port);
    string handleMSG0(Messages::MessageMsg0 m);
    string handleMSG1(Messages::MessageMSG1 msg);
    string handleMSG3(Messages::MessageMSG3 msg);
    string handleAppAttOk();
    void restart();

private:
    static AttestationServer* instance;
    NetworkManagerServer *nm = NULL;
    ServiceProvider *sp = NULL;
    WebService *ws = NULL;
};

#endif











