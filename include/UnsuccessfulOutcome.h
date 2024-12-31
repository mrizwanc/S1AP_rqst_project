/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Descriptions"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_UnsuccessfulOutcome_H_
#define	_UnsuccessfulOutcome_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProcedureCode.h"
#include "Criticality.h"
#include <ANY.h>
#include <asn_ioc.h>
#include "HandoverRequired.h"
#include "HandoverCommand.h"
#include "HandoverPreparationFailure.h"
#include "HandoverRequest.h"
#include "HandoverRequestAcknowledge.h"
#include "HandoverFailure.h"
#include "PathSwitchRequest.h"
#include "PathSwitchRequestAcknowledge.h"
#include "PathSwitchRequestFailure.h"
#include "E-RABSetupRequest.h"
#include "E-RABSetupResponse.h"
#include "E-RABModifyRequest.h"
#include "E-RABModifyResponse.h"
#include "E-RABReleaseCommand.h"
#include "E-RABReleaseResponse.h"
#include "InitialContextSetupRequest.h"
#include "InitialContextSetupResponse.h"
#include "InitialContextSetupFailure.h"
#include "HandoverCancel.h"
#include "HandoverCancelAcknowledge.h"
#include "KillRequest.h"
#include "KillResponse.h"
#include "Reset.h"
#include "ResetAcknowledge.h"
#include "S1SetupRequest.h"
#include "S1SetupResponse.h"
#include "S1SetupFailure.h"
#include "UEContextModificationRequest.h"
#include "UEContextModificationResponse.h"
#include "UEContextModificationFailure.h"
#include "UEContextReleaseCommand.h"
#include "UEContextReleaseComplete.h"
#include "ENBConfigurationUpdate.h"
#include "ENBConfigurationUpdateAcknowledge.h"
#include "ENBConfigurationUpdateFailure.h"
#include "MMEConfigurationUpdate.h"
#include "MMEConfigurationUpdateAcknowledge.h"
#include "MMEConfigurationUpdateFailure.h"
#include "WriteReplaceWarningRequest.h"
#include "WriteReplaceWarningResponse.h"
#include "UERadioCapabilityMatchRequest.h"
#include "UERadioCapabilityMatchResponse.h"
#include "E-RABModificationIndication.h"
#include "E-RABModificationConfirm.h"
#include "HandoverNotify.h"
#include "E-RABReleaseIndication.h"
#include "Paging.h"
#include "DownlinkNASTransport.h"
#include "InitialUEMessage.h"
#include "UplinkNASTransport.h"
#include "ErrorIndication.h"
#include "NASNonDeliveryIndication.h"
#include "UEContextReleaseRequest.h"
#include "DownlinkS1cdma2000tunnelling.h"
#include "UplinkS1cdma2000tunnelling.h"
#include "UECapabilityInfoIndication.h"
#include "ENBStatusTransfer.h"
#include "MMEStatusTransfer.h"
#include "DeactivateTrace.h"
#include "TraceStart.h"
#include "TraceFailureIndication.h"
#include "CellTrafficTrace.h"
#include "LocationReportingControl.h"
#include "LocationReportingFailureIndication.h"
#include "LocationReport.h"
#include "OverloadStart.h"
#include "OverloadStop.h"
#include "ENBDirectInformationTransfer.h"
#include "MMEDirectInformationTransfer.h"
#include "ENBConfigurationTransfer.h"
#include "MMEConfigurationTransfer.h"
#include "PrivateMessage.h"
#include "DownlinkUEAssociatedLPPaTransport.h"
#include "UplinkUEAssociatedLPPaTransport.h"
#include "DownlinkNonUEAssociatedLPPaTransport.h"
#include "UplinkNonUEAssociatedLPPaTransport.h"
#include "PWSRestartIndication.h"
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UnsuccessfulOutcome__value_PR {
	UnsuccessfulOutcome__value_PR_NOTHING,	/* No components present */
	UnsuccessfulOutcome__value_PR_HandoverPreparationFailure,
	UnsuccessfulOutcome__value_PR_HandoverFailure,
	UnsuccessfulOutcome__value_PR_PathSwitchRequestFailure,
	UnsuccessfulOutcome__value_PR_InitialContextSetupFailure,
	UnsuccessfulOutcome__value_PR_S1SetupFailure,
	UnsuccessfulOutcome__value_PR_UEContextModificationFailure,
	UnsuccessfulOutcome__value_PR_ENBConfigurationUpdateFailure,
	UnsuccessfulOutcome__value_PR_MMEConfigurationUpdateFailure
} UnsuccessfulOutcome__value_PR;

/* UnsuccessfulOutcome */
typedef struct UnsuccessfulOutcome {
	ProcedureCode_t	 procedureCode;
	Criticality_t	 criticality;
	struct UnsuccessfulOutcome__value {
		UnsuccessfulOutcome__value_PR present;
		union UnsuccessfulOutcome__value_u {
			HandoverPreparationFailure_t	 HandoverPreparationFailure;
			HandoverFailure_t	 HandoverFailure;
			PathSwitchRequestFailure_t	 PathSwitchRequestFailure;
			InitialContextSetupFailure_t	 InitialContextSetupFailure;
			S1SetupFailure_t	 S1SetupFailure;
			UEContextModificationFailure_t	 UEContextModificationFailure;
			ENBConfigurationUpdateFailure_t	 ENBConfigurationUpdateFailure;
			MMEConfigurationUpdateFailure_t	 MMEConfigurationUpdateFailure;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UnsuccessfulOutcome_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UnsuccessfulOutcome;
extern asn_SEQUENCE_specifics_t asn_SPC_UnsuccessfulOutcome_specs_1;
extern asn_TYPE_member_t asn_MBR_UnsuccessfulOutcome_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _UnsuccessfulOutcome_H_ */
#include <asn_internal.h>
