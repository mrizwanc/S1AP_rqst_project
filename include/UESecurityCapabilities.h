/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_UESecurityCapabilities_H_
#define	_UESecurityCapabilities_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EncryptionAlgorithms.h"
#include "IntegrityProtectionAlgorithms.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* UESecurityCapabilities */
typedef struct UESecurityCapabilities {
	EncryptionAlgorithms_t	 encryptionAlgorithms;
	IntegrityProtectionAlgorithms_t	 integrityProtectionAlgorithms;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UESecurityCapabilities_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UESecurityCapabilities;
extern asn_SEQUENCE_specifics_t asn_SPC_UESecurityCapabilities_specs_1;
extern asn_TYPE_member_t asn_MBR_UESecurityCapabilities_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _UESecurityCapabilities_H_ */
#include <asn_internal.h>
