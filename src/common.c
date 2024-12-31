#include "common.h"


// Function to display the menu
void display_menu() {
    printf("\n\nMenu:\n");
    printf("Press 'u' to send Initial UE Message.\n");
    printf("Press 'q' to quit.\n");
    printf("Your choice: ");
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
    asn_dec_rval_t rval = aper_decode(
        NULL,                        // Optional codec context
        &asn_DEF_S1AP_PDU,           // ASN.1 type descriptor
        (void **)&pdu,               // Pointer to the structure to decode into
        recv_buf,                    // Input buffer
        received,                    // Size of input buffer
        0,                           // skip_bits
        0                            // unused_bits
    );

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

    switch (pdu->present) {
        case S1AP_PDU_PR_initiatingMessage:
            printf("Received an InitiatingMessage from MME\n");
            // Optional: Decode and handle specific initiating messages
            break;

        case S1AP_PDU_PR_successfulOutcome:
            printf("Received a SuccessfulOutcome message from MME.\n");
            // Optional: Decode and handle specific successful outcomes
            break;

        case S1AP_PDU_PR_unsuccessfulOutcome:
            printf("Received an UnsuccessfulOutcome message from MME.\n");
            // Optional: Decode and handle specific unsuccessful outcomes
            break;

        default:
            printf("Received an unknown type of message.\n");
            break;
    }
}


// Print the PDU in a human-readable format
void print_build_pdu(S1AP_PDU_t *pdu) {   
    if (asn_fprint(stdout, &asn_DEF_S1AP_PDU, pdu) < 0) {
        fprintf(stderr, "Failed to print InitialUEMessage PDU\n");
    }
}