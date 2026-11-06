#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_METADATA_SIZE 1024

typedef struct {
    char *ref;
    uint64_t download_size;
    uint64_t installed_size;
    char *eol;
    char *eol_rebase;
} FlatpakTransactionOperation;

typedef struct {
    char *metadata;
    size_t metadata_size;
} FlatpakTransaction;

void resolve_op_end(FlatpakTransaction *self, FlatpakTransactionOperation *op, const char *checksum, const char *sideload_path, void *metadata_bytes) {
    // Simulated end resolution function
}

static void resolve_op_from_commit(FlatpakTransaction *self, FlatpakTransactionOperation *op, const char *checksum, const char *sideload_path, void *commit_data) {
    char *xa_metadata = NULL;
    uint64_t download_size = 0;
    uint64_t installed_size = 0;

    // Simulated parsing of commit_data
    xa_metadata = strstr((char *)commit_data, "xa.metadata");
    if (xa_metadata) {
        xa_metadata += strlen("xa.metadata") + 1;
        size_t metadata_len = strcspn(xa_metadata, "\0");
        if (metadata_len < MAX_METADATA_SIZE) {
            self->metadata = malloc(metadata_len + 1);
            if (self->metadata) {
                memcpy(self->metadata, xa_metadata, metadata_len);
                self->metadata[metadata_len] = '\0';
                self->metadata_size = metadata_len;
            }
        }
    }

    // Simulated lookup of other fields
    download_size = strtoul(strstr((char *)commit_data, "xa.download-size"), NULL, 10);
    installed_size = strtoul(strstr((char *)commit_data, "xa.installed-size"), NULL, 10);

    op->download_size = download_size;
    op->installed_size = installed_size;

    resolve_op_end(self, op, checksum, sideload_path, self->metadata);
}

int main() {
    FlatpakTransaction transaction = {0};
    FlatpakTransactionOperation operation = {0};
    const char *checksum = "dummy_checksum";
    const char *sideload_path = "/dummy/path";
    const char *commit_data = "xa.metadata\0example_metadata\0xa.download-size1024\xa.installed-size2048";

    resolve_op_from_commit(&transaction, &operation, checksum, sideload_path, (void *)commit_data);

    if (transaction.metadata) {
        printf("Metadata: %s\n", transaction.metadata);
        free(transaction.metadata);
    }

    printf("Download Size: %lu\n", operation.download_size);
    printf("Installed Size: %lu\n", operation.installed_size);

    return 0;
}