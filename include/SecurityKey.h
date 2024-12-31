/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_SecurityKey_H_
#define	_SecurityKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SecurityKey */
typedef BIT_STRING_t	 SecurityKey_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_SecurityKey_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_SecurityKey;
asn_struct_free_f SecurityKey_free;
asn_struct_print_f SecurityKey_print;
asn_constr_check_f SecurityKey_constraint;
per_type_decoder_f SecurityKey_decode_aper;
per_type_encoder_f SecurityKey_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _SecurityKey_H_ */
#include <asn_internal.h>
