/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_ManagementBasedMDTAllowed_H_
#define	_ManagementBasedMDTAllowed_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ManagementBasedMDTAllowed {
	ManagementBasedMDTAllowed_allowed	= 0
	/*
	 * Enumeration is extensible
	 */
} e_ManagementBasedMDTAllowed;

/* ManagementBasedMDTAllowed */
typedef long	 ManagementBasedMDTAllowed_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ManagementBasedMDTAllowed_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ManagementBasedMDTAllowed;
extern const asn_INTEGER_specifics_t asn_SPC_ManagementBasedMDTAllowed_specs_1;
asn_struct_free_f ManagementBasedMDTAllowed_free;
asn_struct_print_f ManagementBasedMDTAllowed_print;
asn_constr_check_f ManagementBasedMDTAllowed_constraint;
per_type_decoder_f ManagementBasedMDTAllowed_decode_aper;
per_type_encoder_f ManagementBasedMDTAllowed_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _ManagementBasedMDTAllowed_H_ */
#include <asn_internal.h>