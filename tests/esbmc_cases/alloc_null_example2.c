#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_PACKET_SIZE 1500
#define MAX_OPTIONS 40

struct packet_options {
    uint8_t data[MAX_OPTIONS];
    uint8_t length;
};

struct network_interface {
    struct packet_options *options;
    pthread_rwlock_t lock;
};

struct network_interface *create_interface() {
    struct network_interface *ni = malloc(sizeof(struct network_interface));
    ni->options = NULL;
    pthread_rwlock_init(&ni->lock, NULL);
    return ni;
}

void update_options(struct network_interface *ni, const uint8_t *data, uint8_t length) {
    struct packet_options *new_options = malloc(sizeof(struct packet_options));
    memcpy(new_options->data, data, length);
    new_options->length = length;

    pthread_rwlock_wrlock(&ni->lock);
    struct packet_options *old_options = ni->options;
    ni->options = new_options;
    pthread_rwlock_unlock(&ni->lock);

    // Simulate some processing time
    usleep(1000);

    free(old_options);
}

int parse_packet(struct network_interface *ni, uint8_t *packet, uint16_t length) {
    if (length < 2) return -1;

    uint8_t options_length = packet[1];
    if (options_length > MAX_OPTIONS || length != options_length + 2) return -1;

    pthread_rwlock_rdlock(&ni->lock);
    struct packet_options *current_options = ni->options;
    pthread_rwlock_unlock(&ni->lock);

    if (!current_options) return 0;

    // Process packet using current options
    for (int i = 0; i < current_options->length; i++) {
        // Simulate packet processing
        packet[i] ^= current_options->data[i];
    }

    return 0;
}

void destroy_interface(struct network_interface *ni) {
    pthread_rwlock_wrlock(&ni->lock);
    free(ni->options);
    ni->options = NULL;
    pthread_rwlock_unlock(&ni->lock);
    pthread_rwlock_destroy(&ni->lock);
    free(ni);
}

int main() {
    struct network_interface *ni = create_interface();

    // Update options
    uint8_t options[] = {0x01, 0x02, 0x03, 0x04};
    update_options(ni, options, sizeof(options));

    // Simulate packet processing
    uint8_t packet[MAX_PACKET_SIZE] = {0};
    packet[0] = 0xAA;
    packet[1] = sizeof(options);
    memcpy(packet + 2, options, sizeof(options));

    if (parse_packet(ni, packet, sizeof(options) + 2) == 0) {
        printf("Packet processed successfully\n");
    } else {
        printf("Packet processing failed\n");
    }

    // Clean up
    destroy_interface(ni);

    return 0;
}