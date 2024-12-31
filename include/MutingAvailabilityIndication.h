/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_MutingAvailabilityIndication_H_
#define	_MutingAvailabilityIndication_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MutingAvailabilityIndication {
	MutingAvailabilityIndication_available	= 0,
	MutingAvailabilityIndication_unavailable	= 1
	/*
	 * Enumeration is extensible
	 */
} e_MutingAvailabilityIndication;

/* MutingAvailabilityIndication */
typedef long	 MutingAvailabilityIndication_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MutingAvailabilityIndication_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MutingAvailabilityIndication;
extern const asn_INTEGER_specifics_t asn_SPC_MutingAvailabilityIndication_specs_1;
asn_struct_free_f MutingAvailabilityIndication_free;
asn_struct_print_f MutingAvailabilityIndication_print;
asn_constr_check_f MutingAvailabilityIndication_constraint;
per_type_decoder_f MutingAvailabilityIndication_decode_aper;
per_type_encoder_f MutingAvailabilityIndication_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _MutingAvailabilityIndication_H_ */
#include <asn_internal.h>
