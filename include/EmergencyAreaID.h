/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_EmergencyAreaID_H_
#define	_EmergencyAreaID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EmergencyAreaID */
typedef OCTET_STRING_t	 EmergencyAreaID_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_EmergencyAreaID_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_EmergencyAreaID;
asn_struct_free_f EmergencyAreaID_free;
asn_struct_print_f EmergencyAreaID_print;
asn_constr_check_f EmergencyAreaID_constraint;
per_type_decoder_f EmergencyAreaID_decode_aper;
per_type_encoder_f EmergencyAreaID_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _EmergencyAreaID_H_ */
#include <asn_internal.h>