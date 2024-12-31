/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_CSG_IdList_H_
#define	_CSG_IdList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CSG_IdList_Item;

/* CSG-IdList */
typedef struct CSG_IdList {
	A_SEQUENCE_OF(struct CSG_IdList_Item) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CSG_IdList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CSG_IdList;
extern asn_SET_OF_specifics_t asn_SPC_CSG_IdList_specs_1;
extern asn_TYPE_member_t asn_MBR_CSG_IdList_1[1];
extern asn_per_constraints_t asn_PER_type_CSG_IdList_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _CSG_IdList_H_ */
#include <asn_internal.h>
