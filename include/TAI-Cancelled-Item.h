/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_TAI_Cancelled_Item_H_
#define	_TAI_Cancelled_Item_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TAI.h"
#include "CancelledCellinTAI.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* TAI-Cancelled-Item */
typedef struct TAI_Cancelled_Item {
	TAI_t	 tAI;
	CancelledCellinTAI_t	 cancelledCellinTAI;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TAI_Cancelled_Item_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TAI_Cancelled_Item;
extern asn_SEQUENCE_specifics_t asn_SPC_TAI_Cancelled_Item_specs_1;
extern asn_TYPE_member_t asn_MBR_TAI_Cancelled_Item_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _TAI_Cancelled_Item_H_ */
#include <asn_internal.h>
