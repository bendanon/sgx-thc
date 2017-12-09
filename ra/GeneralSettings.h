#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>
#include "sgx_ecp_types.h"
#define VERIFY_SIGRL
//#define VERIFY_REPORT
using namespace std;
typedef unsigned char byte;

namespace Settings {
	static int rh_port = 22222;
	static string rh_host = "localhost";
	
	static string server_crt = "../server_keys/server.crt"; //certificate for the HTTPS connection between the SP and the App
	static string server_key = "../server_keys/server.key"; //private key for the HTTPS connection

	static string assets_path = "../";

	static const char *skg_enclave_path = "skg_enclave.signed.so";
	static const char *bb_enclave_path = "bb_enclave.signed.so";

	static string spid = "AC7FDD06E124C564BE1E6C666F7BF04B"; //SPID provided by Intel after registration for the IAS service
	static const char *ias_crt = "../../keys/thc.p12"; //location of the certificate send to Intel when registring for the IAS
	static const char *ias_ca = "../../keys/AttestationReportSigningCACert.pem";
	static string ias_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/";
	static const sgx_ec_key_128bit_t const_vk = { 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	// This is the private EC key of SP, the corresponding public EC key is
	// hard coded in isv_enclave. It is based on NIST P-256 curve.
	static const sgx_ec256_private_t sp_priv_key = {
		{
			0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
			0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
			0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
			0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
		}
	};
}

#endif
