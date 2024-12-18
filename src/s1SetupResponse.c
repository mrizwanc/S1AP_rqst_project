#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/sctp.h>

// ASN.1 and S1AP generated headers
#include "S1AP-PDU.h"
#include "SuccessfulOutcome.h"
#include "S1SetupResponse.h"
#include "ServedGUMMEIsItem.h"
#include "ProtocolIE-Field.h"
#include "ProtocolIE-ID.h"
#include "Criticality.h"
#include "ProcedureCode.h"
#include "OCTET_STRING.h"
#include "BIT_STRING.h"
#include "asn_application.h"
#include "asn_internal.h"
#include "per_encoder.h"
#include "per_decoder.h"

// Server Configuration
#define SERVER_PORT 36412
#define BUFFER_SIZE 2048

// Function Prototypes
int setup_sctp_server();
int receive_s1ap_request(int sock);
S1AP_PDU_t *build_s1ap_setup_response();
int encode_s1ap_response(S1AP_PDU_t *pdu, uint8_t **buffer, size_t *buffer_size);
int send_s1ap_response(int sock, uint8_t *buffer, size_t buffer_size);

// Set up SCTP server
int setup_sctp_server() {
    int server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (server_sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 5) < 0) {
        perror("listen");
        close(server_sock);
        return -1;
    }

    printf("MME Server is listening on port %d...\n", SERVER_PORT);
    return server_sock;
}

// Receive and decode S1 Setup Request
int receive_s1ap_request(int sock) {
    uint8_t recv_buf[BUFFER_SIZE];
    ssize_t received = recv(sock, recv_buf, sizeof(recv_buf), 0);
    if (received <= 0) {
        perror("recv");
        return -1;
    }

    printf("Received %ld bytes: Decoding S1 Setup Request...\n", received);

    S1AP_PDU_t *pdu = calloc(1, sizeof(S1AP_PDU_t));
    if (!pdu) {
        perror("calloc failed");
        return -1;
    }

    asn_dec_rval_t rval = aper_decode(NULL, &asn_DEF_S1AP_PDU, (void **)&pdu, recv_buf, received, 0, 0);
    if (rval.code != RC_OK) {
        fprintf(stderr, "Failed to decode S1 Setup Request\n");
        ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
        return -1;
    }

    printf("S1 Setup Request decoded successfully.\n");
    ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
    return 0;
}

// Build S1 Setup Response
S1AP_PDU_t *build_s1ap_setup_response() {
    S1AP_PDU_t *pdu = calloc(1, sizeof(S1AP_PDU_t));
    if (!pdu) return NULL;

    pdu->present = S1AP_PDU_PR_successfulOutcome;
    pdu->choice.successfulOutcome = calloc(1, sizeof(SuccessfulOutcome_t));
    if (!pdu->choice.successfulOutcome) return NULL;

    SuccessfulOutcome_t *outcome = pdu->choice.successfulOutcome;
    outcome->procedureCode = ProcedureCode_id_S1Setup;
    outcome->criticality = Criticality_reject;
    outcome->value.present = SuccessfulOutcome__value_PR_S1SetupResponse;

    S1SetupResponse_t *response = &outcome->value.choice.S1SetupResponse;

    // 1. Add MME Name IE
    S1SetupResponseIEs_t *ie_mme_name = calloc(1, sizeof(S1SetupResponseIEs_t));
    ie_mme_name->id = ProtocolIE_ID_id_MMEname;
    ie_mme_name->criticality = Criticality_ignore;
    ie_mme_name->value.present = S1SetupResponseIEs__value_PR_MMEname;

    OCTET_STRING_fromString(&ie_mme_name->value.choice.MMEname, "open5gs-mme0");
    ASN_SEQUENCE_ADD(&response->protocolIEs.list, ie_mme_name);

    // 2. Add ServedGUMMEIs IE
    S1SetupResponseIEs_t *ie_served_gummeis = calloc(1, sizeof(S1SetupResponseIEs_t));
    ie_served_gummeis->id = ProtocolIE_ID_id_ServedGUMMEIs;
    ie_served_gummeis->criticality = Criticality_reject;
    ie_served_gummeis->value.present = S1SetupResponseIEs__value_PR_ServedGUMMEIs;

    ServedGUMMEIs_t *served_gummeis = &ie_served_gummeis->value.choice.ServedGUMMEIs;
    ServedGUMMEIsItem_t *gummei_item = calloc(1, sizeof(ServedGUMMEIsItem_t));

    // Add servedPLMNs
    PLMNidentity_t *plmn = calloc(1, sizeof(PLMNidentity_t));
    uint8_t plmn_buf[] = {0x00, 0xF1, 0x10}; // MCC=001, MNC=01
    OCTET_STRING_fromBuf(plmn, (char *)plmn_buf, 3);
    ASN_SEQUENCE_ADD(&gummei_item->servedPLMNs.list, plmn);

    // Add servedGroupIDs
    BIT_STRING_t *group_id = calloc(1, sizeof(BIT_STRING_t));
    uint8_t group_buf[] = {0x00, 0x02}; // MME-Group-ID: 2
    group_id->buf = calloc(1, 2);
    memcpy(group_id->buf, group_buf, 2);
    group_id->size = 2;
    group_id->bits_unused = 0;
    ASN_SEQUENCE_ADD(&gummei_item->servedGroupIDs.list, group_id);

    // Add servedMMECs
    BIT_STRING_t *mmec = calloc(1, sizeof(BIT_STRING_t));
    uint8_t mmec_buf[] = {0x01}; // MME-Code: 1
    mmec->buf = calloc(1, 1);
    memcpy(mmec->buf, mmec_buf, 1);
    mmec->size = 1;
    mmec->bits_unused = 0;
    ASN_SEQUENCE_ADD(&gummei_item->servedMMECs.list, mmec);

    ASN_SEQUENCE_ADD(&served_gummeis->list, gummei_item);
    ASN_SEQUENCE_ADD(&response->protocolIEs.list, ie_served_gummeis);

    // 3. Add RelativeMMECapacity IE
    S1SetupResponseIEs_t *ie_relative_capacity = calloc(1, sizeof(S1SetupResponseIEs_t));
    ie_relative_capacity->id = ProtocolIE_ID_id_RelativeMMECapacity;
    ie_relative_capacity->criticality = Criticality_ignore;
    ie_relative_capacity->value.present = S1SetupResponseIEs__value_PR_RelativeMMECapacity;

    ie_relative_capacity->value.choice.RelativeMMECapacity = 255;
    ASN_SEQUENCE_ADD(&response->protocolIEs.list, ie_relative_capacity);

    printf("S1 Setup Response built successfully.\n");
    return pdu;
}


// Encode S1 Setup Response
int encode_s1ap_response(S1AP_PDU_t *pdu, uint8_t **buffer, size_t *buffer_size) {
    ssize_t encoded_size = aper_encode_to_new_buffer(&asn_DEF_S1AP_PDU, NULL, pdu, (void **)buffer);
    if (encoded_size < 0) {
        fprintf(stderr, "Encoding failed\n");
        return -1;
    }

    *buffer_size = encoded_size;
    printf("S1 Setup Response encoded successfully: %zu bytes\n", *buffer_size);
    return 0;
}

// Send S1 Setup Response over SCTP
int send_s1ap_response(int sock, uint8_t *buffer, size_t buffer_size) {
    ssize_t sent_bytes = send(sock, buffer, buffer_size, 0);
    if (sent_bytes < 0) {
        perror("send");
        return -1;
    }

    printf("S1 Setup Response sent: %ld bytes\n", sent_bytes);
    return 0;
}

int main() {
    int server_sock = setup_sctp_server();
    if (server_sock < 0) return EXIT_FAILURE;

    char choice;

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        printf("Waiting for incoming connection...\n");
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Connection established with client: %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        // Receive S1 Setup Request
        if (receive_s1ap_request(client_sock) == 0) {
            // Build and send S1 Setup Response
            S1AP_PDU_t *response_pdu = build_s1ap_setup_response();
            if (response_pdu) {
                uint8_t *encoded_buffer = NULL;
                size_t encoded_size = 0;
                if (encode_s1ap_response(response_pdu, &encoded_buffer, &encoded_size) == 0) {
                    send_s1ap_response(client_sock, encoded_buffer, encoded_size);
                    free(encoded_buffer);
                }
                ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, response_pdu);
            }
        }

        ///close(client_sock);
        //shutdown(client_sock, SHUT_RDWR);

        // Prompt to continue or quit
        printf("S1 interface established. Press 'q' to quit or 'c' to continue: ");
        choice = getchar();
        getchar(); // Consume the newline
        if (choice == 'q') {
            printf("Closing SCTP server.\n");
            break;
        }
    }

    //close(server_sock);
    return EXIT_SUCCESS;
}
