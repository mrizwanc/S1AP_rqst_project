#include "common.h"

#include <sys/socket.h>
#include <unistd.h>

// Define MME IP and PORT (adjust as needed)
#define MME_IP "192.168.0.102"
#define MME_PORT 36412

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

    // Send S1AP Setup Request
    printf("Sending S1AP Setup Request...\n");
    send_s1ap_setup_request(sock);

    
    char choice;
    while (1) {
        display_menu();
        choice = getchar();
        getchar(); // consume newline

        switch (choice) {
            
            case 'u':
                printf("Sending Initial UE Message...\n");
                send_initial_ue_message(sock);
                break;

            case 'q':
                printf("Exiting program and closing SCTP connection.\n");
                close(sock);
                return EXIT_SUCCESS;
                break;

            default:
                printf("Invalid choice! Please try again.\n");
                break;
        }
    }

    return 0;
}