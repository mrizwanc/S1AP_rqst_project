/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_WarningType_H_
#define	_WarningType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WarningType */
typedef OCTET_STRING_t	 WarningType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_WarningType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_WarningType;
asn_struct_free_f WarningType_free;
asn_struct_print_f WarningType_print;
asn_constr_check_f WarningType_constraint;
per_type_decoder_f WarningType_decode_aper;
per_type_encoder_f WarningType_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _WarningType_H_ */
#include <asn_internal.h>
