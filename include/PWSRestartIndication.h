/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_PWSRestartIndication_H_
#define	_PWSRestartIndication_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProtocolIE-Container.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PWSRestartIndication */
typedef struct PWSRestartIndication {
	ProtocolIE_Container_5538P69_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PWSRestartIndication_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PWSRestartIndication;
extern asn_SEQUENCE_specifics_t asn_SPC_PWSRestartIndication_specs_1;
extern asn_TYPE_member_t asn_MBR_PWSRestartIndication_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _PWSRestartIndication_H_ */
#include <asn_internal.h>
