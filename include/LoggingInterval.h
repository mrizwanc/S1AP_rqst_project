/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_LoggingInterval_H_
#define	_LoggingInterval_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LoggingInterval {
	LoggingInterval_ms128	= 0,
	LoggingInterval_ms256	= 1,
	LoggingInterval_ms512	= 2,
	LoggingInterval_ms1024	= 3,
	LoggingInterval_ms2048	= 4,
	LoggingInterval_ms3072	= 5,
	LoggingInterval_ms4096	= 6,
	LoggingInterval_ms6144	= 7
} e_LoggingInterval;

/* LoggingInterval */
typedef long	 LoggingInterval_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LoggingInterval_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LoggingInterval;
extern const asn_INTEGER_specifics_t asn_SPC_LoggingInterval_specs_1;
asn_struct_free_f LoggingInterval_free;
asn_struct_print_f LoggingInterval_print;
asn_constr_check_f LoggingInterval_constraint;
per_type_decoder_f LoggingInterval_decode_aper;
per_type_encoder_f LoggingInterval_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _LoggingInterval_H_ */
#include <asn_internal.h>
