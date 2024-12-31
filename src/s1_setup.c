#include "common.h"


// Build Global-ENB-ID IE
static S1SetupRequestIEs_t *build_global_enb_id_ie() {
    S1SetupRequestIEs_t *ie_global_enb_id = calloc(1, sizeof(S1SetupRequestIEs_t));
    if (!ie_global_enb_id) {
        perror("calloc failed");
        return NULL;
    }

    ie_global_enb_id->id = ProtocolIE_ID_id_Global_ENB_ID;
    ie_global_enb_id->criticality = Criticality_reject;
    ie_global_enb_id->value.present = S1SetupRequestIEs__value_PR_Global_ENB_ID;

    Global_ENB_ID_t *global_enb_id = &ie_global_enb_id->value.choice.Global_ENB_ID;

    // Set PLMN ID: MCC=001, MNC=01
    if (OCTET_STRING_fromBuf(&global_enb_id->pLMNidentity, MCC_MNC_BUF, MCC_MNC_LEN) != 0) {
        perror("OCTET_STRING_fromBuf failed");
        free(ie_global_enb_id);
        return NULL;
    }

    // Example eNB ID (20-bit)
    global_enb_id->eNB_ID.present = ENB_ID_PR_macroENB_ID;
    if (BIT_STRING_fromBuf(&global_enb_id->eNB_ID.choice.macroENB_ID, (uint8_t *)"\xAB\xCD\xEF", 20) != 0) {
        perror("BIT_STRING_fromBuf failed");
        free(ie_global_enb_id);
        return NULL;
    }

    return ie_global_enb_id;
}

// Build SupportedTAs IE
static S1SetupRequestIEs_t *build_supported_tas_ie() {
    S1SetupRequestIEs_t *ie_supported_tas = calloc(1, sizeof(S1SetupRequestIEs_t));
    if (!ie_supported_tas) {
        perror("calloc failed");
        return NULL;
    }

    ie_supported_tas->id = ProtocolIE_ID_id_SupportedTAs;
    ie_supported_tas->criticality = Criticality_ignore;
    ie_supported_tas->value.present = S1SetupRequestIEs__value_PR_SupportedTAs;

    SupportedTAs_t *supported_tas = &ie_supported_tas->value.choice.SupportedTAs;

    SupportedTAs_Item_t *supported_ta_item = calloc(1, sizeof(SupportedTAs_Item_t));
    if (!supported_ta_item) {
        perror("calloc failed");
        free(ie_supported_tas);
        return NULL;
    }

    // TAC = 1
    if (OCTET_STRING_fromBuf(&supported_ta_item->tAC, TAC_BUF, TAC_LEN) != 0) {
        perror("OCTET_STRING_fromBuf failed");
        free(supported_ta_item);
        free(ie_supported_tas);
        return NULL;
    }

    PLMNidentity_t *plmn_id = calloc(1, sizeof(PLMNidentity_t));
    if (!plmn_id) {
        perror("calloc failed");
        free(supported_ta_item);
        free(ie_supported_tas);
        return NULL;
    }

    if (OCTET_STRING_fromBuf(plmn_id, MCC_MNC_BUF, MCC_MNC_LEN) != 0) {
        perror("OCTET_STRING_fromBuf failed");
        free(plmn_id);
        free(supported_ta_item);
        free(ie_supported_tas);
        return NULL;
    }

    if (ASN_SEQUENCE_ADD(&supported_ta_item->broadcastPLMNs.list, plmn_id) != 0) {
        perror("ASN_SEQUENCE_ADD failed");
        free(plmn_id);
        free(supported_ta_item);
        free(ie_supported_tas);
        return NULL;
    }

    if (ASN_SEQUENCE_ADD(&supported_tas->list, supported_ta_item) != 0) {
        perror("ASN_SEQUENCE_ADD failed");
        free(ie_supported_tas);
        return NULL;
    }

    return ie_supported_tas;
}

// Build the entire S1SetupRequest PDU
S1AP_PDU_t *build_s1ap_setup_request() {
    S1AP_PDU_t *pdu = calloc(1, sizeof(S1AP_PDU_t));
    if (!pdu) {
        perror("calloc failed");
        return NULL;
    }

    pdu->present = S1AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = calloc(1, sizeof(InitiatingMessage_t));
    if (!pdu->choice.initiatingMessage) {
        perror("calloc failed");
        free(pdu);
        return NULL;
    }

    InitiatingMessage_t *init_msg = pdu->choice.initiatingMessage;
    init_msg->procedureCode = ProcedureCode_id_S1Setup;
    init_msg->criticality = Criticality_reject;
    init_msg->value.present = InitiatingMessage__value_PR_S1SetupRequest;

    S1SetupRequest_t *setup_request = &init_msg->value.choice.S1SetupRequest;

    // Add Global ENB ID IE
    S1SetupRequestIEs_t *ie_global_enb_id = build_global_enb_id_ie();
    if (!ie_global_enb_id) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    if (ASN_SEQUENCE_ADD(&setup_request->protocolIEs.list, ie_global_enb_id) != 0) {
        perror("ASN_SEQUENCE_ADD failed");
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    // Add SupportedTAs IE
    S1SetupRequestIEs_t *ie_supported_tas = build_supported_tas_ie();
    if (!ie_supported_tas) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    if (ASN_SEQUENCE_ADD(&setup_request->protocolIEs.list, ie_supported_tas) != 0) {
        perror("ASN_SEQUENCE_ADD failed");
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    return pdu;
}



void send_s1ap_setup_request(int sock) {
    // Build S1AP Setup Request
    S1AP_PDU_t *pdu = build_s1ap_setup_request();
    if (!pdu) {
        fprintf(stderr, "Failed to build S1AP Setup Request\n");
        return;
    }

    // Encode the PDU
    uint8_t *encoded_buffer = NULL;
    size_t encoded_size = 0;
    if (encode_s1ap_pdu(pdu, &encoded_buffer, &encoded_size) != 0) {
        fprintf(stderr, "Failed to encode S1AP Setup Request\n");
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return;
    }

    // Send the message with PPID
    if (send_s1ap_message_with_ppid(sock, encoded_buffer, encoded_size, PPID_S1AP) != 0) {
        fprintf(stderr, "Failed to send S1AP Setup Request\n");
        free(encoded_buffer);
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return;
    }
    printf("S1AP Setup Request sent successfully\n");

    // Cleanup
    free(encoded_buffer);
    ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);


    // After sending, let's try to receive the response
    printf("Waiting for S1 Setup Response...\n");


    // Receive and process the S1AP message
    if (receive_s1ap_message(sock) != 0) {
        printf("Failed to receive or decode S1AP message.\n");
        return;
    }

    // At this point, the S1 interface is established. We keep the connection open.
    printf("S1 interface established.");
}