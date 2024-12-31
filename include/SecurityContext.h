/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_SecurityContext_H_
#define	_SecurityContext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "SecurityKey.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* SecurityContext */
typedef struct SecurityContext {
	long	 nextHopChainingCount;
	SecurityKey_t	 nextHopParameter;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SecurityContext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SecurityContext;
extern asn_SEQUENCE_specifics_t asn_SPC_SecurityContext_specs_1;
extern asn_TYPE_member_t asn_MBR_SecurityContext_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _SecurityContext_H_ */
#include <asn_internal.h>