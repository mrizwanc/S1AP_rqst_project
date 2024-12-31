/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_ENBIndirectX2TransportLayerAddresses_H_
#define	_ENBIndirectX2TransportLayerAddresses_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TransportLayerAddress.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ENBIndirectX2TransportLayerAddresses */
typedef struct ENBIndirectX2TransportLayerAddresses {
	A_SEQUENCE_OF(TransportLayerAddress_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ENBIndirectX2TransportLayerAddresses_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ENBIndirectX2TransportLayerAddresses;
extern asn_SET_OF_specifics_t asn_SPC_ENBIndirectX2TransportLayerAddresses_specs_1;
extern asn_TYPE_member_t asn_MBR_ENBIndirectX2TransportLayerAddresses_1[1];
extern asn_per_constraints_t asn_PER_type_ENBIndirectX2TransportLayerAddresses_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _ENBIndirectX2TransportLayerAddresses_H_ */
#include <asn_internal.h>