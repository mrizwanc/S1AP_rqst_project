/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_ExpectedUEActivityBehaviour_H_
#define	_ExpectedUEActivityBehaviour_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ExpectedActivityPeriod.h"
#include "ExpectedIdlePeriod.h"
#include "SourceOfUEActivityBehaviourInformation.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* ExpectedUEActivityBehaviour */
typedef struct ExpectedUEActivityBehaviour {
	ExpectedActivityPeriod_t	*expectedActivityPeriod;	/* OPTIONAL */
	ExpectedIdlePeriod_t	*expectedIdlePeriod;	/* OPTIONAL */
	SourceOfUEActivityBehaviourInformation_t	*sourceofUEActivityBehaviourInformation;	/* OPTIONAL */
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ExpectedUEActivityBehaviour_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ExpectedUEActivityBehaviour;
extern asn_SEQUENCE_specifics_t asn_SPC_ExpectedUEActivityBehaviour_specs_1;
extern asn_TYPE_member_t asn_MBR_ExpectedUEActivityBehaviour_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _ExpectedUEActivityBehaviour_H_ */
#include <asn_internal.h>