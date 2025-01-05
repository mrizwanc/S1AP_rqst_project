#include "common.h"


// Function to display the menu
void display_menu() {
    printf("\n\nMenu:\n");
    printf("Press 'u' to send Initial UE Message.\n");
    printf("Press 'q' to quit.\n");
    printf("Your choice: ");
}

// Function to get the message name from the PDU
const char* get_message_name(S1AP_PDU_t *pdu) {
    if (!pdu) {
        return "Invalid PDU (NULL)";
    }

    int procedureCode = -1;

    switch (pdu->present) {
        case S1AP_PDU_PR_initiatingMessage:
            procedureCode = pdu->choice.initiatingMessage->procedureCode;
            switch (procedureCode) {
                case 0: return "HandoverRequired";
                case 1: return "InitialUEMessage";
                case 2: return "UEContextModificationRequest";
                case 3: return "HandoverRequest";
                case 4: return "UplinkNASTransport";
                case 5: return "DownlinkNASTransport";
                case 6: return "UplinkNASTransport";
                case 11: return "DownlinkNASTransport";
                case 17: return "S1SetupRequest";
                case 19: return "UEContextModificationRequest";
                case 21: return "UEContextReleaseRequest";
                case 22: return "InitialContextSetupRequest";
                case 23: return "UEContextReleaseCommand";
                case 27: return "CreateSessionRequest";
                case 28: return "ModifyBearerRequest";
                case 29: return "BearerResourceModificationRequest";
                case 30: return "CreateBearerRequest";
                case 31: return "DeleteBearerRequest";
                case 34: return "LocationReportingRequest";
                case 35: return "E-RABModificationRequest";
                case 37: return "ResetRequest";
                case 39: return "TraceStartRequest";
                case 41: return "UEContextReleaseRequest";
                default: return "Unknown InitiatingMessage";
            }

        case S1AP_PDU_PR_successfulOutcome:
            procedureCode = pdu->choice.successfulOutcome->procedureCode;
            switch (procedureCode) {
                case 17: return "S1SetupResponse";
                case 20: return "PathSwitchRequestAcknowledge";
                case 23: return "UEContextReleaseComplete";
                case 24: return "InitialContextSetupResponse";
                case 26: return "E-RABModificationResponse";
                case 27: return "UEContextModificationResponse";
                case 31: return "S1AP_NetworkInitiatedBearerResourceCommand";
                case 32: return "CreateSessionResponse";
                case 34: return "ModifyBearerResponse";
                case 35: return "BearerResourceModificationResponse";
                case 36: return "CreateBearerResponse";
                case 37: return "DeleteBearerResponse";
                case 40: return "LocationReportingResponse";
                case 41: return "E-RABSetupResponse";
                case 42: return "UEContextModificationAcknowledge";
                case 43: return "InitialContextSetupAcknowledge";
                default: return "Unknown SuccessfulOutcome";
            }

        case S1AP_PDU_PR_unsuccessfulOutcome:
            procedureCode = pdu->choice.unsuccessfulOutcome->procedureCode;
            switch (procedureCode) {
                case 17: return "S1SetupFailure";
                case 18: return "HandoverFailure";
                case 20: return "PathSwitchRequestFailure";
                case 21: return "UEContextReleaseFailure";
                case 22: return "InitialContextSetupFailure";
                case 23: return "ModifyBearerFailure";
                case 24: return "CreateSessionFailure";
                case 25: return "BearerResourceModificationFailure";
                case 26: return "E-RABModificationFailure";
                case 28: return "BearerResourceModificationFailure";
                case 31: return "LocationReportingFailure";
                case 32: return "DeleteBearerFailure";
                case 33: return "E-RABSetupFailure";
                default: return "Unknown UnsuccessfulOutcome";
            }

        default:
            return "Unknown PDU Type";
    }
}



// Function to create a BIT_STRING from a buffer
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


// Function to encode an S1AP PDU
int encode_s1ap_pdu(S1AP_PDU_t *pdu, uint8_t **buffer, size_t *buffer_size) {
    ssize_t encoded_size = aper_encode_to_new_buffer(&asn_DEF_S1AP_PDU, NULL, pdu, (void **)buffer);
    if (encoded_size < 0) {
        fprintf(stderr, "Encoding failed: Unable to encode PDU\n");
        return -1;
    }

    *buffer_size = (size_t)encoded_size;
    return 0;
}

// Function to send an S1AP message with a specific PPID
int send_s1ap_message_with_ppid(int sock, uint8_t *buffer, size_t buffer_size, uint32_t ppid) {
    ssize_t sent_bytes = sctp_sendmsg(sock, buffer, buffer_size, NULL, 0, htonl(ppid), 0, 0, 0, 0);
    if (sent_bytes < 0) {
        perror("sctp_sendmsg");
        return -1;
    }

    printf("Message sent successfully: %ld bytes, PPID=%d\n", sent_bytes, ppid);
    return 0;
}


// Function to receive and decode an S1AP message
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

    S1AP_PDU_t *pdu = NULL;
    asn_dec_rval_t rval = aper_decode(NULL, &asn_DEF_S1AP_PDU, (void **)&pdu, recv_buf, received, 0, 0);

    if (rval.code != RC_OK) {
        printf("Failed to decode S1AP message. Error code: %d\n", rval.code);
        return -1;
    }

    print_rcvd_msg(pdu);

    ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);

    return 0;
}

// Function to print the decoded S1AP message
void print_rcvd_msg(S1AP_PDU_t *pdu) {
    if (!pdu) {
        printf("S1AP PDU is NULL.\n");
        return;
    }

    // Get message name based on the procedure code
    const char *message_name = get_message_name(pdu);
    int procedureCode = -1;

    switch (pdu->present) {
        case S1AP_PDU_PR_initiatingMessage:
            procedureCode = pdu->choice.initiatingMessage->procedureCode;
            printf("\t\tRecieved InitiatingMessage From MME: \n\t\tName: %s (Code- %d)\n", message_name, procedureCode);
            break;

        case S1AP_PDU_PR_successfulOutcome:
            procedureCode = pdu->choice.successfulOutcome->procedureCode;
            printf("\t\tRecieved SuccessfulOutcome From MME: \n\t\tName: %s (Code- %d)\n", message_name, procedureCode);
            break;

        case S1AP_PDU_PR_unsuccessfulOutcome:
            procedureCode = pdu->choice.unsuccessfulOutcome->procedureCode;
            printf("\t\tReceived UnsuccesfulOutcome From MME: \n\t\tName: %s (Code- %d)\n", message_name, procedureCode);
            break;

        default:
            printf("\t\tReceived Unknown PDU Type.\n");
            break;
    }
}


// Print the PDU in a human-readable format
void print_build_pdu(S1AP_PDU_t *pdu) {   
    if (asn_fprint(stdout, &asn_DEF_S1AP_PDU, pdu) < 0) {
        fprintf(stderr, "Failed to print InitialUEMessage PDU\n");
    }
}