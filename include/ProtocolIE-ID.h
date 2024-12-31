/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-CommonDataTypes"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#ifndef	_ProtocolIE_ID_H_
#define	_ProtocolIE_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ProtocolIE-ID */
typedef long	 ProtocolIE_ID_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ProtocolIE_ID_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_ID;
asn_struct_free_f ProtocolIE_ID_free;
asn_struct_print_f ProtocolIE_ID_print;
asn_constr_check_f ProtocolIE_ID_constraint;
per_type_decoder_f ProtocolIE_ID_decode_aper;
per_type_encoder_f ProtocolIE_ID_encode_aper;
#define ProtocolIE_ID_id_MME_UE_S1AP_ID	((ProtocolIE_ID_t)0)
#define ProtocolIE_ID_id_HandoverType	((ProtocolIE_ID_t)1)
#define ProtocolIE_ID_id_Cause	((ProtocolIE_ID_t)2)
#define ProtocolIE_ID_id_SourceID	((ProtocolIE_ID_t)3)
#define ProtocolIE_ID_id_TargetID	((ProtocolIE_ID_t)4)
#define ProtocolIE_ID_id_eNB_UE_S1AP_ID	((ProtocolIE_ID_t)8)
#define ProtocolIE_ID_id_E_RABSubjecttoDataForwardingList	((ProtocolIE_ID_t)12)
#define ProtocolIE_ID_id_E_RABtoReleaseListHOCmd	((ProtocolIE_ID_t)13)
#define ProtocolIE_ID_id_E_RABDataForwardingItem	((ProtocolIE_ID_t)14)
#define ProtocolIE_ID_id_E_RABReleaseItemBearerRelComp	((ProtocolIE_ID_t)15)
#define ProtocolIE_ID_id_E_RABToBeSetupListBearerSUReq	((ProtocolIE_ID_t)16)
#define ProtocolIE_ID_id_E_RABToBeSetupItemBearerSUReq	((ProtocolIE_ID_t)17)
#define ProtocolIE_ID_id_E_RABAdmittedList	((ProtocolIE_ID_t)18)
#define ProtocolIE_ID_id_E_RABFailedToSetupListHOReqAck	((ProtocolIE_ID_t)19)
#define ProtocolIE_ID_id_E_RABAdmittedItem	((ProtocolIE_ID_t)20)
#define ProtocolIE_ID_id_E_RABFailedtoSetupItemHOReqAck	((ProtocolIE_ID_t)21)
#define ProtocolIE_ID_id_E_RABToBeSwitchedDLList	((ProtocolIE_ID_t)22)
#define ProtocolIE_ID_id_E_RABToBeSwitchedDLItem	((ProtocolIE_ID_t)23)
#define ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq	((ProtocolIE_ID_t)24)
#define ProtocolIE_ID_id_TraceActivation	((ProtocolIE_ID_t)25)
#define ProtocolIE_ID_id_NAS_PDU	((ProtocolIE_ID_t)26)
#define ProtocolIE_ID_id_E_RABToBeSetupItemHOReq	((ProtocolIE_ID_t)27)
#define ProtocolIE_ID_id_E_RABSetupListBearerSURes	((ProtocolIE_ID_t)28)
#define ProtocolIE_ID_id_E_RABFailedToSetupListBearerSURes	((ProtocolIE_ID_t)29)
#define ProtocolIE_ID_id_E_RABToBeModifiedListBearerModReq	((ProtocolIE_ID_t)30)
#define ProtocolIE_ID_id_E_RABModifyListBearerModRes	((ProtocolIE_ID_t)31)
#define ProtocolIE_ID_id_E_RABFailedToModifyList	((ProtocolIE_ID_t)32)
#define ProtocolIE_ID_id_E_RABToBeReleasedList	((ProtocolIE_ID_t)33)
#define ProtocolIE_ID_id_E_RABFailedToReleaseList	((ProtocolIE_ID_t)34)
#define ProtocolIE_ID_id_E_RABItem	((ProtocolIE_ID_t)35)
#define ProtocolIE_ID_id_E_RABToBeModifiedItemBearerModReq	((ProtocolIE_ID_t)36)
#define ProtocolIE_ID_id_E_RABModifyItemBearerModRes	((ProtocolIE_ID_t)37)
#define ProtocolIE_ID_id_E_RABReleaseItem	((ProtocolIE_ID_t)38)
#define ProtocolIE_ID_id_E_RABSetupItemBearerSURes	((ProtocolIE_ID_t)39)
#define ProtocolIE_ID_id_SecurityContext	((ProtocolIE_ID_t)40)
#define ProtocolIE_ID_id_HandoverRestrictionList	((ProtocolIE_ID_t)41)
#define ProtocolIE_ID_id_UEPagingID	((ProtocolIE_ID_t)43)
#define ProtocolIE_ID_id_pagingDRX	((ProtocolIE_ID_t)44)
#define ProtocolIE_ID_id_TAIList	((ProtocolIE_ID_t)46)
#define ProtocolIE_ID_id_TAIItem	((ProtocolIE_ID_t)47)
#define ProtocolIE_ID_id_E_RABFailedToSetupListCtxtSURes	((ProtocolIE_ID_t)48)
#define ProtocolIE_ID_id_E_RABReleaseItemHOCmd	((ProtocolIE_ID_t)49)
#define ProtocolIE_ID_id_E_RABSetupItemCtxtSURes	((ProtocolIE_ID_t)50)
#define ProtocolIE_ID_id_E_RABSetupListCtxtSURes	((ProtocolIE_ID_t)51)
#define ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq	((ProtocolIE_ID_t)52)
#define ProtocolIE_ID_id_E_RABToBeSetupListHOReq	((ProtocolIE_ID_t)53)
#define ProtocolIE_ID_id_GERANtoLTEHOInformationRes	((ProtocolIE_ID_t)55)
#define ProtocolIE_ID_id_UTRANtoLTEHOInformationRes	((ProtocolIE_ID_t)57)
#define ProtocolIE_ID_id_CriticalityDiagnostics	((ProtocolIE_ID_t)58)
#define ProtocolIE_ID_id_Global_ENB_ID	((ProtocolIE_ID_t)59)
#define ProtocolIE_ID_id_eNBname	((ProtocolIE_ID_t)60)
#define ProtocolIE_ID_id_MMEname	((ProtocolIE_ID_t)61)
#define ProtocolIE_ID_id_ServedPLMNs	((ProtocolIE_ID_t)63)
#define ProtocolIE_ID_id_SupportedTAs	((ProtocolIE_ID_t)64)
#define ProtocolIE_ID_id_TimeToWait	((ProtocolIE_ID_t)65)
#define ProtocolIE_ID_id_uEaggregateMaximumBitrate	((ProtocolIE_ID_t)66)
#define ProtocolIE_ID_id_TAI	((ProtocolIE_ID_t)67)
#define ProtocolIE_ID_id_E_RABReleaseListBearerRelComp	((ProtocolIE_ID_t)69)
#define ProtocolIE_ID_id_cdma2000PDU	((ProtocolIE_ID_t)70)
#define ProtocolIE_ID_id_cdma2000RATType	((ProtocolIE_ID_t)71)
#define ProtocolIE_ID_id_cdma2000SectorID	((ProtocolIE_ID_t)72)
#define ProtocolIE_ID_id_SecurityKey	((ProtocolIE_ID_t)73)
#define ProtocolIE_ID_id_UERadioCapability	((ProtocolIE_ID_t)74)
#define ProtocolIE_ID_id_GUMMEI_ID	((ProtocolIE_ID_t)75)
#define ProtocolIE_ID_id_E_RABInformationListItem	((ProtocolIE_ID_t)78)
#define ProtocolIE_ID_id_Direct_Forwarding_Path_Availability	((ProtocolIE_ID_t)79)
#define ProtocolIE_ID_id_UEIdentityIndexValue	((ProtocolIE_ID_t)80)
#define ProtocolIE_ID_id_cdma2000HOStatus	((ProtocolIE_ID_t)83)
#define ProtocolIE_ID_id_cdma2000HORequiredIndication	((ProtocolIE_ID_t)84)
#define ProtocolIE_ID_id_E_UTRAN_Trace_ID	((ProtocolIE_ID_t)86)
#define ProtocolIE_ID_id_RelativeMMECapacity	((ProtocolIE_ID_t)87)
#define ProtocolIE_ID_id_SourceMME_UE_S1AP_ID	((ProtocolIE_ID_t)88)
#define ProtocolIE_ID_id_Bearers_SubjectToStatusTransfer_Item	((ProtocolIE_ID_t)89)
#define ProtocolIE_ID_id_eNB_StatusTransfer_TransparentContainer	((ProtocolIE_ID_t)90)
#define ProtocolIE_ID_id_UE_associatedLogicalS1_ConnectionItem	((ProtocolIE_ID_t)91)
#define ProtocolIE_ID_id_ResetType	((ProtocolIE_ID_t)92)
#define ProtocolIE_ID_id_UE_associatedLogicalS1_ConnectionListResAck	((ProtocolIE_ID_t)93)
#define ProtocolIE_ID_id_E_RABToBeSwitchedULItem	((ProtocolIE_ID_t)94)
#define ProtocolIE_ID_id_E_RABToBeSwitchedULList	((ProtocolIE_ID_t)95)
#define ProtocolIE_ID_id_S_TMSI	((ProtocolIE_ID_t)96)
#define ProtocolIE_ID_id_cdma2000OneXRAND	((ProtocolIE_ID_t)97)
#define ProtocolIE_ID_id_RequestType	((ProtocolIE_ID_t)98)
#define ProtocolIE_ID_id_UE_S1AP_IDs	((ProtocolIE_ID_t)99)
#define ProtocolIE_ID_id_EUTRAN_CGI	((ProtocolIE_ID_t)100)
#define ProtocolIE_ID_id_OverloadResponse	((ProtocolIE_ID_t)101)
#define ProtocolIE_ID_id_cdma2000OneXSRVCCInfo	((ProtocolIE_ID_t)102)
#define ProtocolIE_ID_id_E_RABFailedToBeReleasedList	((ProtocolIE_ID_t)103)
#define ProtocolIE_ID_id_Source_ToTarget_TransparentContainer	((ProtocolIE_ID_t)104)
#define ProtocolIE_ID_id_ServedGUMMEIs	((ProtocolIE_ID_t)105)
#define ProtocolIE_ID_id_SubscriberProfileIDforRFP	((ProtocolIE_ID_t)106)
#define ProtocolIE_ID_id_UESecurityCapabilities	((ProtocolIE_ID_t)107)
#define ProtocolIE_ID_id_CSFallbackIndicator	((ProtocolIE_ID_t)108)
#define ProtocolIE_ID_id_CNDomain	((ProtocolIE_ID_t)109)
#define ProtocolIE_ID_id_E_RABReleasedList	((ProtocolIE_ID_t)110)
#define ProtocolIE_ID_id_MessageIdentifier	((ProtocolIE_ID_t)111)
#define ProtocolIE_ID_id_SerialNumber	((ProtocolIE_ID_t)112)
#define ProtocolIE_ID_id_WarningAreaList	((ProtocolIE_ID_t)113)
#define ProtocolIE_ID_id_RepetitionPeriod	((ProtocolIE_ID_t)114)
#define ProtocolIE_ID_id_NumberofBroadcastRequest	((ProtocolIE_ID_t)115)
#define ProtocolIE_ID_id_WarningType	((ProtocolIE_ID_t)116)
#define ProtocolIE_ID_id_WarningSecurityInfo	((ProtocolIE_ID_t)117)
#define ProtocolIE_ID_id_DataCodingScheme	((ProtocolIE_ID_t)118)
#define ProtocolIE_ID_id_WarningMessageContents	((ProtocolIE_ID_t)119)
#define ProtocolIE_ID_id_BroadcastCompletedAreaList	((ProtocolIE_ID_t)120)
#define ProtocolIE_ID_id_Inter_SystemInformationTransferTypeEDT	((ProtocolIE_ID_t)121)
#define ProtocolIE_ID_id_Inter_SystemInformationTransferTypeMDT	((ProtocolIE_ID_t)122)
#define ProtocolIE_ID_id_Target_ToSource_TransparentContainer	((ProtocolIE_ID_t)123)
#define ProtocolIE_ID_id_SRVCCOperationPossible	((ProtocolIE_ID_t)124)
#define ProtocolIE_ID_id_SRVCCHOIndication	((ProtocolIE_ID_t)125)
#define ProtocolIE_ID_id_NAS_DownlinkCount	((ProtocolIE_ID_t)126)
#define ProtocolIE_ID_id_CSG_Id	((ProtocolIE_ID_t)127)
#define ProtocolIE_ID_id_CSG_IdList	((ProtocolIE_ID_t)128)
#define ProtocolIE_ID_id_SONConfigurationTransferECT	((ProtocolIE_ID_t)129)
#define ProtocolIE_ID_id_SONConfigurationTransferMCT	((ProtocolIE_ID_t)130)
#define ProtocolIE_ID_id_TraceCollectionEntityIPAddress	((ProtocolIE_ID_t)131)
#define ProtocolIE_ID_id_MSClassmark2	((ProtocolIE_ID_t)132)
#define ProtocolIE_ID_id_MSClassmark3	((ProtocolIE_ID_t)133)
#define ProtocolIE_ID_id_RRC_Establishment_Cause	((ProtocolIE_ID_t)134)
#define ProtocolIE_ID_id_NASSecurityParametersfromE_UTRAN	((ProtocolIE_ID_t)135)
#define ProtocolIE_ID_id_NASSecurityParameterstoE_UTRAN	((ProtocolIE_ID_t)136)
#define ProtocolIE_ID_id_DefaultPagingDRX	((ProtocolIE_ID_t)137)
#define ProtocolIE_ID_id_Source_ToTarget_TransparentContainer_Secondary	((ProtocolIE_ID_t)138)
#define ProtocolIE_ID_id_Target_ToSource_TransparentContainer_Secondary	((ProtocolIE_ID_t)139)
#define ProtocolIE_ID_id_EUTRANRoundTripDelayEstimationInfo	((ProtocolIE_ID_t)140)
#define ProtocolIE_ID_id_BroadcastCancelledAreaList	((ProtocolIE_ID_t)141)
#define ProtocolIE_ID_id_ConcurrentWarningMessageIndicator	((ProtocolIE_ID_t)142)
#define ProtocolIE_ID_id_Data_Forwarding_Not_Possible	((ProtocolIE_ID_t)143)
#define ProtocolIE_ID_id_ExtendedRepetitionPeriod	((ProtocolIE_ID_t)144)
#define ProtocolIE_ID_id_CellAccessMode	((ProtocolIE_ID_t)145)
#define ProtocolIE_ID_id_CSGMembershipStatus	((ProtocolIE_ID_t)146)
#define ProtocolIE_ID_id_LPPa_PDU	((ProtocolIE_ID_t)147)
#define ProtocolIE_ID_id_Routing_ID	((ProtocolIE_ID_t)148)
#define ProtocolIE_ID_id_Time_Synchronisation_Info	((ProtocolIE_ID_t)149)
#define ProtocolIE_ID_id_PS_ServiceNotAvailable	((ProtocolIE_ID_t)150)
#define ProtocolIE_ID_id_PagingPriority	((ProtocolIE_ID_t)151)
#define ProtocolIE_ID_id_x2TNLConfigurationInfo	((ProtocolIE_ID_t)152)
#define ProtocolIE_ID_id_eNBX2ExtendedTransportLayerAddresses	((ProtocolIE_ID_t)153)
#define ProtocolIE_ID_id_GUMMEIList	((ProtocolIE_ID_t)154)
#define ProtocolIE_ID_id_GW_TransportLayerAddress	((ProtocolIE_ID_t)155)
#define ProtocolIE_ID_id_Correlation_ID	((ProtocolIE_ID_t)156)
#define ProtocolIE_ID_id_SourceMME_GUMMEI	((ProtocolIE_ID_t)157)
#define ProtocolIE_ID_id_MME_UE_S1AP_ID_2	((ProtocolIE_ID_t)158)
#define ProtocolIE_ID_id_RegisteredLAI	((ProtocolIE_ID_t)159)
#define ProtocolIE_ID_id_RelayNode_Indicator	((ProtocolIE_ID_t)160)
#define ProtocolIE_ID_id_TrafficLoadReductionIndication	((ProtocolIE_ID_t)161)
#define ProtocolIE_ID_id_MDTConfiguration	((ProtocolIE_ID_t)162)
#define ProtocolIE_ID_id_MMERelaySupportIndicator	((ProtocolIE_ID_t)163)
#define ProtocolIE_ID_id_GWContextReleaseIndication	((ProtocolIE_ID_t)164)
#define ProtocolIE_ID_id_ManagementBasedMDTAllowed	((ProtocolIE_ID_t)165)
#define ProtocolIE_ID_id_PrivacyIndicator	((ProtocolIE_ID_t)166)
#define ProtocolIE_ID_id_Time_UE_StayedInCell_EnhancedGranularity	((ProtocolIE_ID_t)167)
#define ProtocolIE_ID_id_HO_Cause	((ProtocolIE_ID_t)168)
#define ProtocolIE_ID_id_VoiceSupportMatchIndicator	((ProtocolIE_ID_t)169)
#define ProtocolIE_ID_id_GUMMEIType	((ProtocolIE_ID_t)170)
#define ProtocolIE_ID_id_M3Configuration	((ProtocolIE_ID_t)171)
#define ProtocolIE_ID_id_M4Configuration	((ProtocolIE_ID_t)172)
#define ProtocolIE_ID_id_M5Configuration	((ProtocolIE_ID_t)173)
#define ProtocolIE_ID_id_MDT_Location_Info	((ProtocolIE_ID_t)174)
#define ProtocolIE_ID_id_MobilityInformation	((ProtocolIE_ID_t)175)
#define ProtocolIE_ID_id_Tunnel_Information_for_BBF	((ProtocolIE_ID_t)176)
#define ProtocolIE_ID_id_ManagementBasedMDTPLMNList	((ProtocolIE_ID_t)177)
#define ProtocolIE_ID_id_SignallingBasedMDTPLMNList	((ProtocolIE_ID_t)178)
#define ProtocolIE_ID_id_ULCOUNTValueExtended	((ProtocolIE_ID_t)179)
#define ProtocolIE_ID_id_DLCOUNTValueExtended	((ProtocolIE_ID_t)180)
#define ProtocolIE_ID_id_ReceiveStatusOfULPDCPSDUsExtended	((ProtocolIE_ID_t)181)
#define ProtocolIE_ID_id_ECGIListForRestart	((ProtocolIE_ID_t)182)
#define ProtocolIE_ID_id_SIPTO_Correlation_ID	((ProtocolIE_ID_t)183)
#define ProtocolIE_ID_id_SIPTO_L_GW_TransportLayerAddress	((ProtocolIE_ID_t)184)
#define ProtocolIE_ID_id_TransportInformation	((ProtocolIE_ID_t)185)
#define ProtocolIE_ID_id_LHN_ID	((ProtocolIE_ID_t)186)
#define ProtocolIE_ID_id_AdditionalCSFallbackIndicator	((ProtocolIE_ID_t)187)
#define ProtocolIE_ID_id_TAIListForRestart	((ProtocolIE_ID_t)188)
#define ProtocolIE_ID_id_UserLocationInformation	((ProtocolIE_ID_t)189)
#define ProtocolIE_ID_id_EmergencyAreaIDListForRestart	((ProtocolIE_ID_t)190)
#define ProtocolIE_ID_id_KillAllWarningMessages	((ProtocolIE_ID_t)191)
#define ProtocolIE_ID_id_Masked_IMEISV	((ProtocolIE_ID_t)192)
#define ProtocolIE_ID_id_eNBIndirectX2TransportLayerAddresses	((ProtocolIE_ID_t)193)
#define ProtocolIE_ID_id_uE_HistoryInformationFromTheUE	((ProtocolIE_ID_t)194)
#define ProtocolIE_ID_id_ProSeAuthorized	((ProtocolIE_ID_t)195)
#define ProtocolIE_ID_id_ExpectedUEBehaviour	((ProtocolIE_ID_t)196)
#define ProtocolIE_ID_id_LoggedMBSFNMDT	((ProtocolIE_ID_t)197)
#define ProtocolIE_ID_id_UERadioCapabilityForPaging	((ProtocolIE_ID_t)198)
#define ProtocolIE_ID_id_E_RABToBeModifiedListBearerModInd	((ProtocolIE_ID_t)199)
#define ProtocolIE_ID_id_E_RABToBeModifiedItemBearerModInd	((ProtocolIE_ID_t)200)
#define ProtocolIE_ID_id_E_RABNotToBeModifiedListBearerModInd	((ProtocolIE_ID_t)201)
#define ProtocolIE_ID_id_E_RABNotToBeModifiedItemBearerModInd	((ProtocolIE_ID_t)202)
#define ProtocolIE_ID_id_E_RABModifyListBearerModConf	((ProtocolIE_ID_t)203)
#define ProtocolIE_ID_id_E_RABModifyItemBearerModConf	((ProtocolIE_ID_t)204)
#define ProtocolIE_ID_id_E_RABFailedToModifyListBearerModConf	((ProtocolIE_ID_t)205)
#define ProtocolIE_ID_id_SON_Information_Report	((ProtocolIE_ID_t)206)
#define ProtocolIE_ID_id_Muting_Availability_Indication	((ProtocolIE_ID_t)207)
#define ProtocolIE_ID_id_Muting_Pattern_Information	((ProtocolIE_ID_t)208)
#define ProtocolIE_ID_id_Synchronisation_Information	((ProtocolIE_ID_t)209)
#define ProtocolIE_ID_id_E_RABToBeReleasedListBearerModConf	((ProtocolIE_ID_t)210)

#ifdef __cplusplus
}
#endif

#endif	/* _ProtocolIE_ID_H_ */
#include <asn_internal.h>
