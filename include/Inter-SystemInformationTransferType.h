/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_Inter_SystemInformationTransferType_H_
#define	_Inter_SystemInformationTransferType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Inter_SystemInformationTransferType_PR {
	Inter_SystemInformationTransferType_PR_NOTHING,	/* No components present */
	Inter_SystemInformationTransferType_PR_rIMTransfer
	/* Extensions may appear below */
	
} Inter_SystemInformationTransferType_PR;

/* Forward declarations */
struct RIMTransfer;

/* Inter-SystemInformationTransferType */
typedef struct Inter_SystemInformationTransferType {
	Inter_SystemInformationTransferType_PR present;
	union Inter_SystemInformationTransferType_u {
		struct RIMTransfer	*rIMTransfer;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Inter_SystemInformationTransferType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Inter_SystemInformationTransferType;
extern asn_CHOICE_specifics_t asn_SPC_Inter_SystemInformationTransferType_specs_1;
extern asn_TYPE_member_t asn_MBR_Inter_SystemInformationTransferType_1[1];
extern asn_per_constraints_t asn_PER_type_Inter_SystemInformationTransferType_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Inter_SystemInformationTransferType_H_ */
#include <asn_internal.h>
