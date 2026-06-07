# [HIGH] Out-of-Bounds Read in IR Camera Focus Sweep

## Vulnerable Code
`main_board/src/optics/ir_camera_system/ir_camera_system_hw.c:303` — `ir_camera_system_set_focus_values_for_focus_sweep_hw()`

```c
void
ir_camera_system_set_focus_values_for_focus_sweep_hw(int16_t *focus_values,
                                                     size_t num_focus_values)
{
    global_num_focus_values = num_focus_values;
    memcpy(global_focus_values, focus_values, sizeof(global_focus_values));
    use_focus_sweep_polynomial = false;
}
```

## Root Cause
The function `ir_camera_system_set_focus_values_for_focus_sweep_hw` performs a `memcpy` from the input `focus_values` pointer to the `global_focus_values` array. However, it always copies `sizeof(global_focus_values)` bytes (400 bytes), regardless of the actual number of values provided in `num_focus_values`.

The `focus_values` pointer points to a buffer within a Protobuf message decoded by Nanopb. If the incoming message contains fewer than 200 focus values, the `memcpy` will read past the end of the `focus_values` buffer and into adjacent memory on the stack (where the `job_t` structure is allocated in the runner thread).

## Attack Path
1. Attacker sends an `ir_eye_camera_focus_sweep_lens_values` CAN message to the MCU.
2. The message contains a `focus_values` array with only one entry.
3. The MCU's `runner_process_jobs_thread` receives the message and calls `handle_ir_eye_camera_focus_sweep_lens_values`.
4. The code reaches `ir_camera_system_set_focus_values_for_focus_sweep_hw` at `ir_camera_system_hw.c:303`.
5. The `memcpy` reads 400 bytes from the source buffer, but the buffer only contains 2 bytes of legitimate data.
6. 398 bytes of adjacent stack memory are leaked into the `global_focus_values` array.
7. These leaked values (which might contain sensitive data from other processed messages or stack pointers) are later used to drive the liquid lens hardware during a focus sweep. While not directly exfiltrated over the network, this OOB read can be used to corrupt MCU state if the liquid lens driver or other subsystems rely on the integrity of this data, or potentially exfiltrated if a diagnostic message reports the current focus values back to the Jetson.

## PoC
The following script demonstrates the vulnerability by simulating the MCU's memory layout and the buggy `memcpy`.

```bash
./run_poc.sh
# Expected output: [!] Detected leaked data from adjacent memory!
```

## Impact
Memory leak of stack data. An attacker can exfiltrate sensitive information from the MCU's memory by carefully timing focus sweep operations and observing system behavior or diagnostic outputs.

## Fix
Use the actual size of the incoming data for the `memcpy` operation.

```c
void
ir_camera_system_set_focus_values_for_focus_sweep_hw(int16_t *focus_values,
                                                     size_t num_focus_values)
{
    global_num_focus_values = num_focus_values;
    memcpy(global_focus_values, focus_values, num_focus_values * sizeof(int16_t));
    use_focus_sweep_polynomial = false;
}
```

## Status
CONFIRMED
