/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_NAS_PDU_H_
#define	_NAS_PDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NAS-PDU */
typedef OCTET_STRING_t	 NAS_PDU_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NAS_PDU;
asn_struct_free_f NAS_PDU_free;
asn_struct_print_f NAS_PDU_print;
asn_constr_check_f NAS_PDU_constraint;
per_type_decoder_f NAS_PDU_decode_aper;
per_type_encoder_f NAS_PDU_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NAS_PDU_H_ */
#include <asn_internal.h>
