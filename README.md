# Topology Hiding Computation implemeted over Intel SGX

The code requires the installation of Intel SGX [here](https://github.com/01org/linux-sgx) and 
the SGX driver [here](https://github.com/01org/linux-sgx-driver). Furthermore, also a developer account
for the usage of IAS has be registered [Deverloper account](https://software.intel.com/en-us/sgx).
After the registration with a certificate (can be self-signed for development purposes), Intel will
respond with a SPID which is needed to communicate with IAS. 

The code consists of two separate programs, the SkgApplication and the BbApplication.
For a single topology, there should be a single SkgApplication instance and multiple interconnected BbApplication instances. There is a Flask based GUI for users running BbApplication.
The message exchange over the network is performed using Google Protocol Buffers. 

## Installation

Before running the code, some settings have to be set in the ```GeneralSettings.h``` file:
* The application port and IP 
* A server certificate and private key are required for the SSL communication between the SP and the Application (which can be self-signed)<br /> 
e.g. ```openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.crt -days 365```
* The SPID provided by Intel when registering for the developer account
* The certificate sent to Intel when registering for the developer account
* IAS Rest API url (should stay the same)

To be able to run the above code some external libraries are needed:

* Google Protocol Buffers (should already be installed with the SGX SDK package) otherwise install ```libprotobuf-dev```, ```libprotobuf-c0-dev``` and ```protobuf-compiler```

All other required libraries can be installed with the following command
```sudo apt-get install libboost-thread-dev libboost-system-dev curl libcurl4-openssl-dev libssl-dev liblog4cpp5-dev libjsoncpp-dev```

Also, you need to clone the wolfssl repo:
```cd ../ ; git clone https://github.com/wolfSSL/wolfssl.git```

After the installation of those dependencies, the code can be compiled with the following commands:<br/>
```cd SkgApplication```
```./makerelease```
```cd ../BbApplication```
```./makerelease``` <br \>

IMPORTANT - make sure that if you make changes to the skg enclave, you need to run it once, look for a debug print such as
```INFO  : skg mrenclave is h39gowM7F0Au0m6JfC1DoMO6K1GImzd3MXHK9HAwsP8=```
And hard-code the mrenclave value (h39gowM7F0Au0m6JfC1DoMO6K1GImzd3MXHK9HAwsP8=) into the variable "skg_mrenclave" inside the bb_enclave.cpp file, then recompile the bb_enclave

## Notes
The SGX driver might have problems starting after reboot. You would recognize this problem when either SKG or BB applications output
```ERROR  : Error, call sgx_create_enclave fail``` <br \>
```INFO  : sgx_create_enclave() needs the AE service to get a launch token``` <br \>
```INFO  : createEnclave failed``` <br \>
To solve this problem, got into the linux-sgx-driver source directory, type
```make clean``` <br />
and follow the steps specified in linux-sgx-driver/README.md file. Then type:
```$ sudo aesmd service start```

