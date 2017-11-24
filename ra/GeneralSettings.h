#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>
//#define NO_HW_SUPPORT
using namespace std;

namespace Settings {
	static int rh_port = 22222;
	static string rh_host = "localhost";
	
	static string server_crt = "../server_keys/server.crt"; //certificate for the HTTPS connection between the SP and the App
	static string server_key = "../server_keys/server.key"; //private key for the HTTPS connection

	static string assets_path = "../";

	static string spid = "AC7FDD06E124C564BE1E6C666F7BF04B"; //SPID provided by Intel after registration for the IAS service
	static const char *ias_crt = "../../keys/thc.p12"; //location of the certificate send to Intel when registring for the IAS
	static string ias_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/";
}

#endif
