/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_LastVisitedCell_Item_H_
#define	_LastVisitedCell_Item_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LastVisitedUTRANCellInformation.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LastVisitedCell_Item_PR {
	LastVisitedCell_Item_PR_NOTHING,	/* No components present */
	LastVisitedCell_Item_PR_e_UTRAN_Cell,
	LastVisitedCell_Item_PR_uTRAN_Cell,
	LastVisitedCell_Item_PR_gERAN_Cell
	/* Extensions may appear below */
	
} LastVisitedCell_Item_PR;

/* Forward declarations */
struct LastVisitedEUTRANCellInformation;
struct LastVisitedGERANCellInformation;

/* LastVisitedCell-Item */
typedef struct LastVisitedCell_Item {
	LastVisitedCell_Item_PR present;
	union LastVisitedCell_Item_u {
		struct LastVisitedEUTRANCellInformation	*e_UTRAN_Cell;
		LastVisitedUTRANCellInformation_t	 uTRAN_Cell;
		struct LastVisitedGERANCellInformation	*gERAN_Cell;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LastVisitedCell_Item_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LastVisitedCell_Item;
extern asn_CHOICE_specifics_t asn_SPC_LastVisitedCell_Item_specs_1;
extern asn_TYPE_member_t asn_MBR_LastVisitedCell_Item_1[3];
extern asn_per_constraints_t asn_PER_type_LastVisitedCell_Item_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LastVisitedCell_Item_H_ */
#include <asn_internal.h>
