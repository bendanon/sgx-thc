#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h> // or jsoncpp/json.h , or json/json.h etc.

using namespace std;

void createJson();

int main( int argc, char **argv ) {
    if(argc != 2){
        cout << "Usage: ./app <config_file_name>.json" << endl;
        return -1;
    }
    
    ifstream ifs(argv[1]);
    Json::Reader reader;
    Json::Value obj;
    reader.parse(ifs, obj); // reader can also read strings
    cout << "Local ID: " << obj["local_id"].asUInt() << endl;
    cout << "Port: " << obj["port"].asUInt() << endl;
    const Json::Value& neighbors = obj["neighbors"]; // array of neighbors
    for (int i = 0; i < neighbors.size(); i++){
        cout << "id: " << neighbors[i]["id"].asUInt();
        cout << "  ip: " << neighbors[i]["ip"].asString();
        cout << "  port: " << neighbors[i]["port"].asUInt();
        cout << endl;
    }

    createJson();
}

void createJson(){
    Json::Value neighbors;
    neighbors[0]["id"] = 2;
    neighbors[0]["ip"] = "127.0.0.1";
    neighbors[0]["port"] = 4442;
    neighbors[1]["id"] = 5;
    neighbors[1]["ip"] = "127.0.0.1";
    neighbors[1]["port"] = 4445;
    neighbors[2]["id"] = 6;
    neighbors[2]["ip"] = "127.0.0.1";
    neighbors[2]["port"] = 4446;
    neighbors[3]["id"] = 7;
    neighbors[4]["ip"] = "127.0.0.1";
    neighbors[4]["port"] = 4447;

    // create the main object
    Json::Value val;
    val["local_id"] = 4;
    val["port"] = 4444;
    val["neighbors"] = neighbors;

    
    cout << val.toStyledString() << '\n';
}