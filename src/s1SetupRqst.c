#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/sctp.h>

// Include ASN.1 and S1AP generated headers
#include "S1AP-PDU.h"
#include "InitiatingMessage.h"
#include "S1SetupRequest.h"
#include "Global-ENB-ID.h"
#include "SupportedTAs.h"
#include "SupportedTAs-Item.h"
#include "ProtocolIE-Field.h"
#include "ProtocolIE-ID.h"
#include "Criticality.h"
#include "ProcedureCode.h"
#include "ENB-ID.h"
#include "BIT_STRING.h"
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "asn_internal.h"
#include "per_encoder.h"
#include "per_decoder.h"  // For aper_decode()

// Define MME IP and PORT (adjust as needed)
#define MME_IP "192.168.0.102"
#define MME_PORT 36412

// Define PLMN and TAC
#define MCC_MNC_BUF "\x00\xF1\x10" // MCC=001, MNC=01
#define MCC_MNC_LEN 3
#define TAC_BUF "\x00\x01"
#define TAC_LEN 2

#define BUFFER_SIZE 2048

int BIT_STRING_fromBuf(BIT_STRING_t *bit_str, const uint8_t *buf, size_t bit_len);
S1AP_PDU_t *build_s1ap_setup_request();
int encode_s1ap_pdu(S1AP_PDU_t *pdu, uint8_t **buffer, size_t *buffer_size);
int send_s1ap_message(int sock, uint8_t *buffer, size_t buffer_size);
int receive_s1ap_message(int sock);
void print_s1ap_pdu(S1AP_PDU_t *pdu);

//
// Utility function to fill a BIT_STRING structure from a buffer.
//
int BIT_STRING_fromBuf(BIT_STRING_t *bit_str, const uint8_t *buf, size_t bit_len) {
    if (!bit_str || !buf) {
        fprintf(stderr, "BIT_STRING_fromBuf: Invalid parameters\n");
        return -1;
    }

    bit_str->buf = calloc(1, (bit_len + 7) / 8);
    if (!bit_str->buf) {
        perror("calloc failed");
        return -1;
    }

    memcpy(bit_str->buf, buf, (bit_len + 7) / 8);
    bit_str->size = (bit_len + 7) / 8;
    bit_str->bits_unused = 8 - (bit_len % 8);
    if (bit_str->bits_unused == 8) bit_str->bits_unused = 0;

    return 0;
}

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

// Encode the S1AP PDU using APER
int encode_s1ap_pdu(S1AP_PDU_t *pdu, uint8_t **buffer, size_t *buffer_size) {
    ssize_t encoded_size = aper_encode_to_new_buffer(&asn_DEF_S1AP_PDU, NULL, pdu, (void **)buffer);
    if (encoded_size < 0) {
        fprintf(stderr, "Encoding failed: Unable to encode PDU\n");
        return -1;
    }

    *buffer_size = (size_t)encoded_size;
    return 0;
}

// Send S1AP message to MME via SCTP
int send_s1ap_message(int sock, uint8_t *buffer, size_t buffer_size) {
    ssize_t sent_bytes = send(sock, buffer, buffer_size, 0);
    if (sent_bytes < 0) {
        perror("send");
        return -1;
    }

    printf("Message sent successfully: %ld bytes\n", sent_bytes);
    return 0;
}

// Receive and decode S1AP message from MME
int receive_s1ap_message(int sock) {
    uint8_t recv_buf[BUFFER_SIZE];
    ssize_t received = recv(sock, recv_buf, sizeof(recv_buf), 0);
    if (received < 0) {
        perror("recv");
        return -1;
    } else if (received == 0) {
        printf("MME closed the connection.\n");
        return -1;
    }

    printf("Received %ld bytes from MME\n", received);

    // Decode the received message
    S1AP_PDU_t *pdu = calloc(1, sizeof(S1AP_PDU_t));
    if (!pdu) {
        perror("calloc failed");
        return -1;
    }

    // Provide skip_bits=0 and unused_bits=0 as required by aper_decode signature
    asn_dec_rval_t rval = aper_decode(
        NULL,                 // No special codec context
        &asn_DEF_S1AP_PDU,    // The type descriptor
        (void **)&pdu,        // Pointer to output structure
        recv_buf,             // Input buffer
        received,             // Size of input buffer
        0,                    // skip_bits
        0                     // unused_bits
    );

    if (rval.code != RC_OK) {
        fprintf(stderr, "Decoding failed with code %d\n", rval.code);
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return -1;
    }

    // Print and understand the PDU
    print_s1ap_pdu(pdu);

    ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
    return 0;
}

// A simple print function to understand the response PDU
void print_s1ap_pdu(S1AP_PDU_t *pdu) {
    switch (pdu->present) {
        case S1AP_PDU_PR_initiatingMessage:
            printf("Received an InitiatingMessage from MME (Unexpected for S1 Setup Response)\n");
            break;
        case S1AP_PDU_PR_successfulOutcome:
            printf("Received a SuccessfulOutcome message from MME. Probably an S1 Setup Response.\n");
            // Further parsing of pdu->choice.successfulOutcome->value.choice.S1SetupResponse is possible here.
            break;
        case S1AP_PDU_PR_unsuccessfulOutcome:
            printf("Received an UnsuccessfulOutcome message from MME. S1 Setup failed.\n");
            break;
        default:
            printf("Received an unknown type of message.\n");
            break;
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in mme_addr = {0};
    mme_addr.sin_family = AF_INET;
    mme_addr.sin_port = htons(MME_PORT);
    if (inet_pton(AF_INET, MME_IP, &mme_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return EXIT_FAILURE;
    }

    if (connect(sock, (struct sockaddr *)&mme_addr, sizeof(mme_addr)) < 0) {
        perror("connect");
        close(sock);
        return EXIT_FAILURE;
    }
    printf("SCTP connection established with MME.\n");

    // Build S1AP Setup Request
    S1AP_PDU_t *pdu = build_s1ap_setup_request();
    if (!pdu) {
        fprintf(stderr, "Failed to build S1AP Setup Request\n");
        close(sock);
        return EXIT_FAILURE;
    }

    // Encode the PDU
    uint8_t *encoded_buffer = NULL;
    size_t encoded_size = 0;
    if (encode_s1ap_pdu(pdu, &encoded_buffer, &encoded_size) != 0) {
        fprintf(stderr, "Failed to encode S1AP Setup Request\n");
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        close(sock);
        return EXIT_FAILURE;
    }

    // Send the message
    if (send_s1ap_message(sock, encoded_buffer, encoded_size) != 0) {
        fprintf(stderr, "Failed to send S1AP Setup Request\n");
        free(encoded_buffer);
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        close(sock);
        return EXIT_FAILURE;
    }

    free(encoded_buffer);
    ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);

    // After sending, let's try to receive the response
    printf("Waiting for S1 Setup Response...\n");
    if (receive_s1ap_message(sock) != 0) {
        fprintf(stderr, "Failed to receive or decode S1AP response\n");
        // If you want to handle a failure scenario differently, you can do so here.
        // But we won't close the connection immediately, depending on your use case.
    }

    // At this point, the S1 interface is established. We keep the connection open.
    // You can implement a loop here to send further messages or wait for incoming ones.

    printf("S1 interface established. Press 'q' to quit or 'c' to continue: ");
    char choice;
    while ((choice = getchar()) != EOF) {
        getchar(); // consume newline
        if (choice == 'q') {
            printf("Closing SCTP connection.\n");
            break;
        } else if (choice == 'c') {
            // If 'c', continue sending or receiving messages as needed.
            // For example, you might send another S1AP message here.
            printf("You chose to continue. Implement further logic here.\n");
        } else {
            printf("Press 'q' to quit or 'c' to continue.\n");
        }
    }

    // Close the connection only when you decide to quit.
    close(sock);
    return EXIT_SUCCESS;
}
