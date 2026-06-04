#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Mocking the BBRAM device and its functions
uint8_t mock_bbram[10] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33};

int bbram_read(void *dev, uint16_t offset, size_t size, uint8_t *data) {
    if (offset + size > 10) return -1;
    memcpy(data, &mock_bbram[offset], size);
    return 0;
}

// The vulnerable function from lib/storage/backup_regs.c
int backup_regs_read_byte(const size_t offset, uint8_t *data) {
    // BUG: uses sizeof(data) which is the size of the pointer (4 or 8 bytes)
    size_t size_to_read = sizeof(data);
    printf("[!] backup_regs_read_byte: pointer size is %zu. Reading %zu bytes into %p\n", sizeof(data), size_to_read, (void*)data);
    return bbram_read(NULL, offset, size_to_read, data);
}

// Mimicking app_init_state from main_board/src/power/boot/boot.c
void app_init_state_sim() {
    uint8_t buffer[16];
    memset(buffer, 0xEE, sizeof(buffer));

    uint8_t *boot_flag_ptr = &buffer[4]; // Put it in the middle

    printf("[+] Before call:\n");
    printf("    Buffer: ");
    for(int i=0; i<16; i++) printf("%02x ", buffer[i]);
    printf("\n");

    backup_regs_read_byte(0, boot_flag_ptr);

    printf("[+] After call:\n");
    printf("    Buffer: ");
    for(int i=0; i<16; i++) printf("%02x ", buffer[i]);
    printf("\n");

    int corrupted = 0;
    for(int i=5; i<4 + sizeof(void*); i++) {
        if (buffer[i] != 0xEE) corrupted = 1;
    }

    if (corrupted) {
        printf("\n[!] BUFFER CORRUPTION DETECTED beyond the first byte!\n");
    } else {
        printf("\n[?] No corruption detected.\n");
    }
}

int main() {
    printf("--- Orb Firmware Stack Overflow PoC ---\n");
    app_init_state_sim();
    return 0;
}
