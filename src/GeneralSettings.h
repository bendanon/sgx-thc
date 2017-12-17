#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>
#include "sgx_ecp_types.h"
#include "th_definitions.h"

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

	// This is the public EC key of the SP. The corresponding private EC key is
	// used by the SP to sign data used in the remote attestation SIGMA protocol
	// to sign channel binding data in MSG2. A successful verification of the
	// signature confirms the identity of the SP to the ISV app in remote
	// attestation secure channel binding. The public EC key should be hardcoded in
	// the enclave or delivered in a trustworthy manner. The use of a spoofed public
	// EC key in the remote attestation with secure channel binding session may lead
	// to a security compromise. Every different SP the enlcave communicates to
	// must have a unique SP public key. Delivery of the SP public key is
	// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
	// based on NIST P-256
	static const sgx_ec256_public_t sp_pub_key = {
		{
			0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
			0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
			0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
			0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
		},
		{
			0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
			0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
			0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
			0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
		}

	};
}

#endif
