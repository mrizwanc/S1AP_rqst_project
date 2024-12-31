/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_UERadioCapabilityForPaging_H_
#define	_UERadioCapabilityForPaging_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UERadioCapabilityForPaging */
typedef OCTET_STRING_t	 UERadioCapabilityForPaging_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UERadioCapabilityForPaging;
asn_struct_free_f UERadioCapabilityForPaging_free;
asn_struct_print_f UERadioCapabilityForPaging_print;
asn_constr_check_f UERadioCapabilityForPaging_constraint;
per_type_decoder_f UERadioCapabilityForPaging_decode_aper;
per_type_encoder_f UERadioCapabilityForPaging_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _UERadioCapabilityForPaging_H_ */
#include <asn_internal.h>
