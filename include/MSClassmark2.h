/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_MSClassmark2_H_
#define	_MSClassmark2_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MSClassmark2 */
typedef OCTET_STRING_t	 MSClassmark2_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MSClassmark2;
asn_struct_free_f MSClassmark2_free;
asn_struct_print_f MSClassmark2_print;
asn_constr_check_f MSClassmark2_constraint;
per_type_decoder_f MSClassmark2_decode_aper;
per_type_encoder_f MSClassmark2_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _MSClassmark2_H_ */
#include <asn_internal.h>
