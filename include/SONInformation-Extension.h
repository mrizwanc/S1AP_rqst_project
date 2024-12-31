/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_SONInformation_Extension_H_
#define	_SONInformation_Extension_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProtocolIE-SingleContainer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SONInformation-Extension */
typedef ProtocolIE_SingleContainer_5541P15_t	 SONInformation_Extension_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SONInformation_Extension;
asn_struct_free_f SONInformation_Extension_free;
asn_struct_print_f SONInformation_Extension_print;
asn_constr_check_f SONInformation_Extension_constraint;
per_type_decoder_f SONInformation_Extension_decode_aper;
per_type_encoder_f SONInformation_Extension_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _SONInformation_Extension_H_ */
#include <asn_internal.h>