#ifndef _IAS_RA_H
#define _IAS_RA_H

#include "ecp.h"
#include "sgx_quote.h"

#include "LogBase.h"

using namespace util;

typedef enum {
    IAS_QUOTE_OK,
    IAS_QUOTE_SIGNATURE_INVALID,
    IAS_QUOTE_GROUP_REVOKED,
    IAS_QUOTE_SIGNATURE_REVOKED,
    IAS_QUOTE_KEY_REVOKED,
    IAS_QUOTE_SIGRL_VERSION_MISMATCH,
    IAS_QUOTE_GROUP_OUT_OF_DATE,
} ias_quote_status_t;

// These status should align with the definition in IAS API spec(rev 0.6)
typedef enum {
    IAS_PSE_OK,
    IAS_PSE_DESC_TYPE_NOT_SUPPORTED,
    IAS_PSE_ISVSVN_OUT_OF_DATE,
    IAS_PSE_MISCSELECT_INVALID,
    IAS_PSE_ATTRIBUTES_INVALID,
    IAS_PSE_MRSIGNER_INVALID,
    IAS_PS_HW_GID_REVOKED,
    IAS_PS_HW_PRIVKEY_RLVER_MISMATCH,
    IAS_PS_HW_SIG_RLVER_MISMATCH,
    IAS_PS_HW_CA_ID_INVALID,
    IAS_PS_HW_SEC_INFO_INVALID,
    IAS_PS_HW_PSDA_SVN_OUT_OF_DATE,
} ias_pse_status_t;

// Revocation Reasons from RFC5280
typedef enum {
    IAS_REVOC_REASON_NONE,
    IAS_REVOC_REASON_KEY_COMPROMISE,
    IAS_REVOC_REASON_CA_COMPROMISED,
    IAS_REVOC_REASON_SUPERCEDED,
    IAS_REVOC_REASON_CESSATION_OF_OPERATION,
    IAS_REVOC_REASON_CERTIFICATE_HOLD,
    IAS_REVOC_REASON_PRIVILEGE_WITHDRAWN,
    IAS_REVOC_REASON_AA_COMPROMISE,
} ias_revoc_reason_t;

// These status should align with the definition in IAS API spec(rev 0.6)
#define IAS_EPID_GROUP_STATUS_REVOKED_BIT_POS           0x00
#define IAS_EPID_GROUP_STATUS_REKEY_AVAILABLE_BIT_POS   0x01

#define IAS_TCB_EVAL_STATUS_CPUSVN_OUT_OF_DATE_BIT_POS  0x00
#define IAS_TCB_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS  0x01

#define IAS_PSE_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS  0x00
#define IAS_PSE_EVAL_STATUS_EPID_GROUP_REVOKED_BIT_POS  0x01
#define IAS_PSE_EVAL_STATUS_PSDASVN_OUT_OF_DATE_BIT_POS 0x02
#define IAS_PSE_EVAL_STATUS_SIGRL_OUT_OF_DATE_BIT_POS   0x03
#define IAS_PSE_EVAL_STATUS_PRIVRL_OUT_OF_DATE_BIT_POS  0x04

// These status should align with the definition in IAS API spec(rev 0.6)
#define ISVSVN_SIZE         2
#define PSDA_SVN_SIZE       4
#define GID_SIZE            4
#define PSVN_SIZE           18

#define SAMPLE_HASH_SIZE    32  // SHA256
#define SAMPLE_MAC_SIZE     16  // Message Authentication Code
// - 16 bytes

#define SAMPLE_REPORT_DATA_SIZE         64

typedef uint8_t             sample_measurement_t[SAMPLE_HASH_SIZE];
typedef uint8_t             sample_mac_t[SAMPLE_MAC_SIZE];
typedef uint8_t             sample_report_data_t[SAMPLE_REPORT_DATA_SIZE];
typedef uint16_t            sample_prod_id_t;

#define SAMPLE_CPUSVN_SIZE  16

typedef uint8_t             sample_cpu_svn_t[SAMPLE_CPUSVN_SIZE];
typedef uint16_t            sample_isv_svn_t;

typedef struct sample_attributes_t {
    uint64_t                flags;
    uint64_t                xfrm;
} sample_attributes_t;

typedef struct sample_report_body_t {
    sample_cpu_svn_t        cpu_svn;        // (  0) Security Version of the CPU
    uint8_t                 reserved1[32];  // ( 16)
    sample_attributes_t     attributes;     // ( 48) Any special Capabilities
    //       the Enclave possess
    sample_measurement_t    mr_enclave;     // ( 64) The value of the enclave's
    //       ENCLAVE measurement
    uint8_t                 reserved2[32];  // ( 96)
    sample_measurement_t    mr_signer;      // (128) The value of the enclave's
    //       SIGNER measurement
    uint8_t                 reserved3[32];  // (160)
    sample_measurement_t    mr_reserved1;   // (192)
    sample_measurement_t    mr_reserved2;   // (224)
    sample_prod_id_t        isv_prod_id;    // (256) Product ID of the Enclave
    sample_isv_svn_t        isv_svn;        // (258) Security Version of the
    //       Enclave
    uint8_t                 reserved4[60];  // (260)
    sample_report_data_t    report_data;    // (320) Data provided by the user
} sample_report_body_t;

#pragma pack(push, 1)

typedef struct _ias_att_report_t {
    char                    id[100];
    ias_quote_status_t      status;
    uint32_t                revocation_reason;
    ias_platform_info_blob_t    info_blob;
    ias_pse_status_t        pse_status;
    uint32_t                policy_report_size;
    uint8_t                 policy_report[];// IAS_Q: Why does it specify a list of reports?
} ias_att_report_t;

  /** TODO
     * "id":"<report_id>",
       "isvEnclaveQuoteStatus":"<quote_status>",           (probably not needed here)
       "isvEnclaveQuoteBody":"<quote_body>",               (===> V2)
       "platformInfoBlob":"<platform_info_blob><optional>", 
       "revocationReason":<recovation_reason><optional>,  
       "pseManifestStatus": "<manifest_status><optional>",
       "pseManifestHash": "<pse_manifest_hash><optional>", (===> V2)
       "nonce":"<custom_value_passed_by_caller><optional>", (probably not needed here)
       "epidPseudonym":"<epid_pseudonym_for_linkable><optional>", (probably not needed here)
       "timestamp":"<timestamp>"                            (probably not needed here)
     **/

#define SAMPLE_QUOTE_UNLINKABLE_SIGNATURE 0
#define SAMPLE_QUOTE_LINKABLE_SIGNATURE   1

#pragma pack(pop)

#endif
