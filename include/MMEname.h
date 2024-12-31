/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_MMEname_H_
#define	_MMEname_H_


#include <asn_application.h>

/* Including external dependencies */
#include <PrintableString.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MMEname */
typedef PrintableString_t	 MMEname_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MMEname_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MMEname;
asn_struct_free_f MMEname_free;
asn_struct_print_f MMEname_print;
asn_constr_check_f MMEname_constraint;
per_type_decoder_f MMEname_decode_aper;
per_type_encoder_f MMEname_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _MMEname_H_ */
#include <asn_internal.h>
