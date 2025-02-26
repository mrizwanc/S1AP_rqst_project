/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_PriorityLevel_H_
#define	_PriorityLevel_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PriorityLevel {
	PriorityLevel_spare	= 0,
	PriorityLevel_highest	= 1,
	PriorityLevel_lowest	= 14,
	PriorityLevel_no_priority	= 15
} e_PriorityLevel;

/* PriorityLevel */
typedef long	 PriorityLevel_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PriorityLevel_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PriorityLevel;
asn_struct_free_f PriorityLevel_free;
asn_struct_print_f PriorityLevel_print;
asn_constr_check_f PriorityLevel_constraint;
per_type_decoder_f PriorityLevel_decode_aper;
per_type_encoder_f PriorityLevel_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _PriorityLevel_H_ */
#include <asn_internal.h>
