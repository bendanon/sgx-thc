#include "AttestationServer.h"
#include "../GeneralSettings.h"

#include  <iomanip>

using namespace util;
using namespace std;

AttestationServer* AttestationServer::instance = NULL;

AttestationServer::AttestationServer(int port) {
    this->nm = NetworkManagerServer::getInstance(port);
    this->ws = WebService::getInstance();
    this->ws->init();
    this->sp = new ServiceProvider(this->ws);
}


AttestationServer::~AttestationServer() {}


AttestationServer* AttestationServer::getInstance() {
    if (instance == NULL) {
        instance = new AttestationServer();
    }

    return instance;
}


int AttestationServer::init() {
    if (this->sp) {
        delete this->sp;
        this->sp = new ServiceProvider(this->ws);
    }

    this->nm->Init();
    this->nm->connectCallbackHandler([this](string v, int type) {
        return this->incomingHandler(v, type);
    });
}


void AttestationServer::start() {
    this->nm->startService();
    Log("Remote attestation done");
}


string AttestationServer::handleMSG0(Messages::MessageMsg0 msg) {
    Log("MSG0 received");

    if (msg.status() != TYPE_TERMINATE) {
        uint32_t extended_epid_group_id = msg.epid();
        int ret = this->sp->sp_ra_proc_msg0_req(extended_epid_group_id);

        if (ret == 0) {
            msg.set_status(TYPE_OK);
            return nm->serialize(msg);
        }
    } else {
        Log("Termination received!");
    }
    
    return "";    
}


string AttestationServer::handleMSG1(Messages::MessageMSG1 msg1) {
    Log("MSG1 received");

    Messages::MessageMSG2 msg2;
    msg2.set_type(RA_MSG2);

    int ret = this->sp->sp_ra_proc_msg1_req(msg1, &msg2);

    if (ret != 0) {
        Log("Error, processing MSG1 failed");
    } else {
        Log("MSG1 processed correctly and MSG2 created");
        return nm->serialize(msg2);
    }

    return "";
}


string AttestationServer::handleMSG3(Messages::MessageMSG3 msg) {
    Log("MSG3 received");

    Messages::MessageMSG4 att_msg;
    att_msg.set_type(RA_ATT_RESULT);

    int ret = this->sp->sp_ra_proc_msg3_req(msg, att_msg);

    if (ret == -1) {
        Log("Error, processing MSG3 failed");
    } else {
        Log("MSG3 processed correctly and attestation result created");
        return nm->serialize(att_msg);
    }

    return "";
}


string AttestationServer::handleAppAttOk() {
    Log("APP attestation result received");
    return "";
}

void AttestationServer::restart()
{
    //TODO: Maybe re-initialize some session state?
}

vector<string> AttestationServer::incomingHandler(string v, int type) {
    vector<string> res;
    string s;
    bool ret;

    if(type == RA_FAILED_READ)
    {
        Log("AttestationServer::incomingHandler - Failed read, restarting");
        restart();
        return res;
    }

    switch (type) {
        case RA_MSG0: {
            Messages::MessageMsg0 msg0;
            ret = msg0.ParseFromString(v);
            if (ret && (msg0.type() == RA_MSG0)) {
                s = this->handleMSG0(msg0);
                res.push_back(to_string(RA_MSG0));
            }
        }
        break;
        case RA_MSG1: {
            Messages::MessageMSG1 msg1;
            ret = msg1.ParseFromString(v);
            if (ret && (msg1.type() == RA_MSG1)) {
                s = this->handleMSG1(msg1);
                res.push_back(to_string(RA_MSG2));
            }
        }
        break;
        case RA_MSG3: {
            Messages::MessageMSG3 msg3;
            ret = msg3.ParseFromString(v);
            if (ret && (msg3.type() == RA_MSG3)) {
                s = this->handleMSG3(msg3);
                res.push_back(to_string(RA_ATT_RESULT));
            }
        }
        break;
        case RA_APP_ATT_OK: {
            Messages::SecretMessage sec_msg;
            ret = sec_msg.ParseFromString(v);
            if (ret) {
                if (sec_msg.type() == RA_APP_ATT_OK) {
                    this->handleAppAttOk();
                }
            }
        }
        break;
        default:
            Log("Unknown type: %d", type, log::error);
            break;
    }

    res.push_back(s);

    return res;
}




















