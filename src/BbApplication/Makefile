######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SUPPLIED_KEY_DERIVATION), 1)
        SGX_COMMON_CFLAGS += -DSUPPLIED_KEY_DERIVATION
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif


App_Cpp_Files := bb_app/bb_app.cpp ../Util/LogBase.cpp ../Networking/NetworkManager.cpp ../Networking/Session.cpp ../Networking/Server.cpp \
../Networking/Client.cpp ../Networking/NetworkManagerClient.cpp ../Networking/NetworkManagerServer.cpp ../GoogleMessages/Messages.pb.cpp ../Networking/AbstractNetworkOps.cpp \
../Util/UtilityFunctions.cpp ../Enclave/Enclave.cpp ../Enclave/BbEnclave.cpp ../AttestationClient/AttestationClient.cpp ../Util/Base64.cpp ../VerificationReport/VerificationReport.cpp \
../BbClient/BbClient.cpp ../WebService/WebService.cpp

App_Include_Paths := -I../Util -Isample_libcrypto -I$(SGX_SDK)/include -Iheaders  -I../Networking -Ibb_app -I../GoogleMessages -I/usr/local/include -I../Enclave \
-I../AttestationClient -I../VerificationReport -I../BbClient -I../Networking -I../WebService -Isample_libcrypto

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -lsample_libcrypto -Lsample_libcrypto

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	#App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11 -DEnableServer -DEnableClient
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -lsgx_ukey_exchange -lpthread -lsample_libcrypto -Lsample_libcrypto -Wl,-rpath=$(CURDIR) -llog4cpp -lboost_system -L/usr/lib -lssl -lcrypto -lboost_thread -lprotobuf -L /usr/local/lib -ljsoncpp -lcurl


ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app


######## Enclave Settings ########
ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

bb_Enclave_Cpp_Files := BlackBoxExecuter/BlackBoxExecuter.cpp bb_enclave/bb_enclave.cpp ../common_enclave/common_enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/crypto_px/include -I../Enclave/ -IBlackBoxExecuter

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
bb_Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=bb_enclave/bb_enclave.lds

bb_Enclave_Cpp_Objects := $(bb_Enclave_Cpp_Files:.cpp=.o)

bb_Enclave_Name := bb_enclave.so
bb_Signed_Enclave_Name := bb_enclave.signed.so
bb_Enclave_Config_File := bb_enclave/bb_enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(bb_Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(bb_Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(bb_Enclave_Name) -out <$(bb_Signed_Enclave_Name)> -config $(bb_Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(bb_Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name) 	
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## App Objects ########

bb_app/bb_enclave_u.c: $(SGX_EDGER8R) bb_enclave/bb_enclave.edl
	@cd bb_app && $(SGX_EDGER8R) --untrusted ../bb_enclave/bb_enclave.edl --search-path ../bb_enclave --search-path $(SGX_SDK)/include --search-path ../../common_enclave
	@echo "GEN  =>  $@"

bb_app/bb_enclave_u.o: bb_app/bb_enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

bb_app/%.o: bb_app/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

../AttestationClient/%.o: ../AttestationClient/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

../Util/%.o: ../Util/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

../Networking/%.o: ../Networking/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

../Enclave/%.o: ../Enclave/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

../VerificationReport/%.o: ../VerificationReport/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -Wl,-rpath=$(CURDIR)/sample_libcrypto -lsample_libcrypto -o $@
	@echo "CXX  <=  $<"

../WebService/%.o: ../WebService/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

../BlackBoxExecuter/%.o: ../BlackBoxExecuter/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

../BbClient/%.o: ../BbClient/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"


$(App_Name): bb_app/bb_enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## common Enclave Objects ########

../common_enclave/%.o: ../common_enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

######## BB Enclave Objects ########

bb_enclave/bb_enclave_t.c: $(SGX_EDGER8R) bb_enclave/bb_enclave.edl
	@cd bb_enclave && $(SGX_EDGER8R) --trusted ../bb_enclave/bb_enclave.edl --search-path ../bb_enclave --search-path $(SGX_SDK)/include --search-path ../../common_enclave
	@echo "GEN  =>  $@"

bb_enclave/bb_enclave_t.o: bb_enclave/bb_enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

bb_enclave/%.o: bb_enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(bb_Enclave_Name): bb_enclave/bb_enclave_t.o $(bb_Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(bb_Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(bb_Signed_Enclave_Name): $(bb_Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key bb_enclave/bb_enclave_private.pem -enclave $(bb_Enclave_Name) -out $@ -config $(bb_Enclave_Config_File)
	@echo "SIGN =>  $@"
.PHONY: clean

clean:
	@rm -f $(App_Name) $(bb_Enclave_Name) $(bb_Signed_Enclave_Name) $(App_Cpp_Objects) bb_app/bb_enclave_u.* $(bb_Enclave_Cpp_Objects) bb_enclave/bb_enclave_t.* libservice_provider.* $(ServiceProvider_Cpp_Objects)
