#include "common.h"




// Build eNB UE S1AP ID IE
static InitialUEMessage_IEs_t *build_enb_ue_s1ap_id_ie(uint32_t enb_ue_s1ap_id) {
    InitialUEMessage_IEs_t *ie = calloc(1, sizeof(InitialUEMessage_IEs_t));
    if (!ie) {
        perror("calloc failed");
        return NULL;
    }

    ie->id = ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = Criticality_reject;
    ie->value.present = InitialUEMessage_IEs__value_PR_ENB_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = enb_ue_s1ap_id;

    return ie;
}

// Build NAS PDU IE
static InitialUEMessage_IEs_t *build_nas_pdu_ie(const uint8_t *nas_pdu_buf, size_t nas_pdu_len) {
    InitialUEMessage_IEs_t *ie = calloc(1, sizeof(InitialUEMessage_IEs_t));
    if (!ie) {
        perror("calloc failed");
        return NULL;
    }

    ie->id = ProtocolIE_ID_id_NAS_PDU;
    ie->criticality = Criticality_reject;
    ie->value.present = InitialUEMessage_IEs__value_PR_NAS_PDU;

    if (OCTET_STRING_fromBuf(&ie->value.choice.NAS_PDU, (const char *)nas_pdu_buf, nas_pdu_len) != 0) {
        perror("OCTET_STRING_fromBuf failed");
        free(ie);
        return NULL;
    }

    return ie;
}

// Build TAI IE
static InitialUEMessage_IEs_t *build_tai_ie() {
    InitialUEMessage_IEs_t *ie = calloc(1, sizeof(InitialUEMessage_IEs_t));
    if (!ie) {
        perror("calloc failed");
        return NULL;
    }

    ie->id = ProtocolIE_ID_id_TAI;
    ie->criticality = Criticality_reject;
    ie->value.present = InitialUEMessage_IEs__value_PR_TAI;

    TAI_t *tai = &ie->value.choice.TAI;

    if (OCTET_STRING_fromBuf(&tai->pLMNidentity, MCC_MNC_BUF, MCC_MNC_LEN) != 0) {
        perror("OCTET_STRING_fromBuf failed");
        free(ie);
        return NULL;
    }

    if (OCTET_STRING_fromBuf(&tai->tAC, TAC_BUF, TAC_LEN) != 0) {
        perror("OCTET_STRING_fromBuf failed");
        free(ie);
        return NULL;
    }
    return ie;
}

// Build EUTRAN CGI IE
static InitialUEMessage_IEs_t *build_eutran_cgi_ie() {
    InitialUEMessage_IEs_t *ie = calloc(1, sizeof(InitialUEMessage_IEs_t));
    if (!ie) {
        perror("calloc failed");
        return NULL;
    }

    ie->id = ProtocolIE_ID_id_EUTRAN_CGI;
    ie->criticality = Criticality_ignore;
    ie->value.present = InitialUEMessage_IEs__value_PR_EUTRAN_CGI;

    EUTRAN_CGI_t *cgi = &ie->value.choice.EUTRAN_CGI;

    // Set PLMN ID
    if (OCTET_STRING_fromBuf(&cgi->pLMNidentity, MCC_MNC_BUF, MCC_MNC_LEN) != 0) {
        perror("OCTET_STRING_fromBuf failed");
        free(ie);
        return NULL;
    }

    // Set Cell ID
    cgi->cell_ID.buf = malloc(CELL_ID_LEN);
    if (!cgi->cell_ID.buf) {
        perror("malloc failed for cell_ID");
        free(ie);
        return NULL;
    }

    memcpy(cgi->cell_ID.buf, CELL_ID_BUF, CELL_ID_LEN);
    cgi->cell_ID.size = CELL_ID_LEN;
    cgi->cell_ID.bits_unused = 4; // Indicate 28 valid bits in a 32-bit buffer



    return ie;
}

// Build RRC Establishment Cause IE
static InitialUEMessage_IEs_t *build_rrc_establishment_cause_ie(int cause) {
    InitialUEMessage_IEs_t *ie = calloc(1, sizeof(InitialUEMessage_IEs_t));
    if (!ie) {
        perror("calloc failed");
        return NULL;
    }

    ie->id = ProtocolIE_ID_id_RRC_Establishment_Cause;
    ie->criticality = Criticality_ignore;
    ie->value.present = InitialUEMessage_IEs__value_PR_RRC_Establishment_Cause;
    ie->value.choice.RRC_Establishment_Cause = cause;

    return ie;
}

// Build the entire InitialUEMessage PDU
S1AP_PDU_t *build_initial_ue_message() {
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
    init_msg->procedureCode = ProcedureCode_id_initialUEMessage;
    init_msg->criticality = Criticality_ignore;
    init_msg->value.present = InitiatingMessage__value_PR_InitialUEMessage;

    InitialUEMessage_t *initial_ue_message = &init_msg->value.choice.InitialUEMessage;

    // Add eNB UE S1AP ID IE
    InitialUEMessage_IEs_t *ie_enb_ue_s1ap_id = build_enb_ue_s1ap_id_ie(0);
    if (!ie_enb_ue_s1ap_id || ASN_SEQUENCE_ADD(&initial_ue_message->protocolIEs.list, ie_enb_ue_s1ap_id) != 0) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    // Add NAS PDU IE
    uint8_t nas_pdu[] = {0x07, 0x41, 0x72, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x86,
                            0x92, 0x07, 0xf0, 0x70, 0xc0, 0x40, 0x19, 0x00, 0x80, 0x00, 0x05,
                            0x02, 0x07, 0xd0, 0x31, 0xd1, 0x5c, 0x0a, 0x00, 0x31, 0x04, 0x65,
                            0xe0, 0x3e, 0x00, 0x90, 0x11, 0x03, 0x57, 0x58, 0xa6, 0x20, 0x0d,
                            0x60, 0x14, 0x04, 0xef, 0x65, 0x23, 0x3b, 0x88, 0x78, 0xd2, 0xf2,
                            0x80, 0x00, 0x40, 0x08, 0x04, 0x02, 0x60, 0x04, 0x00, 0x02, 0x1f,
                            0x00, 0x5d, 0x01, 0x03, 0xc1};
    InitialUEMessage_IEs_t *ie_nas_pdu = build_nas_pdu_ie(nas_pdu, sizeof(nas_pdu));
    if (!ie_nas_pdu || ASN_SEQUENCE_ADD(&initial_ue_message->protocolIEs.list, ie_nas_pdu) != 0) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    // Add TAI IE
    InitialUEMessage_IEs_t *ie_tai = build_tai_ie();
    if (!ie_tai || ASN_SEQUENCE_ADD(&initial_ue_message->protocolIEs.list, ie_tai) != 0) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    // Add EUTRAN CGI IE
    InitialUEMessage_IEs_t *ie_eutran_cgi = build_eutran_cgi_ie();
    if (!ie_eutran_cgi || ASN_SEQUENCE_ADD(&initial_ue_message->protocolIEs.list, ie_eutran_cgi) != 0) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    // Add RRC Establishment Cause IE
    InitialUEMessage_IEs_t *ie_rrc_cause = build_rrc_establishment_cause_ie(RRC_Establishment_Cause_mo_Signalling);
    if (!ie_rrc_cause || ASN_SEQUENCE_ADD(&initial_ue_message->protocolIEs.list, ie_rrc_cause) != 0) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return NULL;
    }

    printf("\nInitial UE Message built successfully\n");

    return pdu;
}


void send_initial_ue_message(int sock) {
    // Build Initial UE Message
    S1AP_PDU_t *pdu = build_initial_ue_message();
    if (!pdu) {
        fprintf(stderr, "Failed to build Initial UE Message\n");
        return;
    }

    uint8_t *encoded_buffer = NULL;
    size_t encoded_size = 0;

    // Encode the PDU
    if (encode_s1ap_pdu(pdu, &encoded_buffer, &encoded_size) != 0) {
        fprintf(stderr, "Failed to encode Initial UE Message\n");
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return;
    }


    // Send the message with PPID
    if (send_s1ap_message_with_ppid(sock, encoded_buffer, encoded_size, PPID_S1AP) != 0) {
        fprintf(stderr, "Failed to send Initial UE Message\n");
        free(encoded_buffer);
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return;
    }

    printf("Initial UE Message sent successfully\n");

    // Cleanup
    free(encoded_buffer);
    ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);


    // After sending, let's try to receive the response
    printf("Waiting for response...\n");


    // Receive and process the S1AP message
    if (receive_s1ap_message(sock) != 0) {
        printf("Failed to receive or decode S1AP message.\n");
        return;
    }

}