/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_AreaScopeOfMDT_H_
#define	_AreaScopeOfMDT_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AreaScopeOfMDT_PR {
	AreaScopeOfMDT_PR_NOTHING,	/* No components present */
	AreaScopeOfMDT_PR_cellBased,
	AreaScopeOfMDT_PR_tABased,
	AreaScopeOfMDT_PR_pLMNWide,
	/* Extensions may appear below */
	AreaScopeOfMDT_PR_tAIBased
} AreaScopeOfMDT_PR;

/* Forward declarations */
struct CellBasedMDT;
struct TABasedMDT;
struct TAIBasedMDT;

/* AreaScopeOfMDT */
typedef struct AreaScopeOfMDT {
	AreaScopeOfMDT_PR present;
	union AreaScopeOfMDT_u {
		struct CellBasedMDT	*cellBased;
		struct TABasedMDT	*tABased;
		NULL_t	 pLMNWide;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
		struct TAIBasedMDT	*tAIBased;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AreaScopeOfMDT_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AreaScopeOfMDT;
extern asn_CHOICE_specifics_t asn_SPC_AreaScopeOfMDT_specs_1;
extern asn_TYPE_member_t asn_MBR_AreaScopeOfMDT_1[4];
extern asn_per_constraints_t asn_PER_type_AreaScopeOfMDT_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _AreaScopeOfMDT_H_ */
#include <asn_internal.h>