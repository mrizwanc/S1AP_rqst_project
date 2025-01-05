#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <arpa/inet.h>
#include <netinet/sctp.h>

// Include ASN.1 and S1AP generated headers
#include "asn_codecs.h"
#include "S1AP-PDU.h"
#include "InitiatingMessage.h"
#include "SuccessfulOutcome.h"
#include "UnsuccessfulOutcome.h"
#include "InitialUEMessage.h"
#include "S1SetupRequest.h"
#include "Global-ENB-ID.h"
#include "SupportedTAs.h"
#include "SupportedTAs-Item.h"
#include "ProtocolIE-Field.h"
#include "ProtocolIE-ID.h"
#include "Criticality.h"
#include "ProcedureCode.h"
#include "ENB-ID.h"
#include "EUTRAN-CGI.h"
#include "TAI.h"
#include "RRC-Establishment-Cause.h"
#include "BIT_STRING.h"
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "asn_internal.h"
#include "per_encoder.h"
#include "per_decoder.h"

// Define constants
#define MCC_MNC_BUF "\x00\xF1\x10" // MCC=001, MNC=01
#define MCC_MNC_LEN 3
#define TAC_BUF "\x00\x01"
#define TAC_LEN 2
#define CELL_ID_BUF "\x1A\x21\xD4\xB0"
#define CELL_ID_LEN 4
#define BUFFER_SIZE 2048
#define PPID_S1AP 18 // PPID for S1AP messages

// Function prototypes

void display_menu();
int BIT_STRING_fromBuf(BIT_STRING_t *bit_str, const uint8_t *buf, size_t bit_len);
int encode_s1ap_pdu(S1AP_PDU_t *pdu, uint8_t **buffer, size_t *buffer_size);
int send_s1ap_message_with_ppid(int sock, uint8_t *buffer, size_t buffer_size, uint32_t ppid);
int receive_s1ap_message(int sock);
void print_rcvd_msg(S1AP_PDU_t *pdu);
void print_build_pdu(S1AP_PDU_t *pdu);

S1AP_PDU_t *build_s1ap_setup_request();
void send_s1ap_setup_request(int sock);

S1AP_PDU_t *build_initial_ue_message();
void send_initial_ue_message(int sock);


#endif //COMMON_H