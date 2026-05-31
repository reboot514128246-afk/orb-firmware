# [HIGH] Out-of-Bounds Read in `ir_camera_system_set_focus_values_for_focus_sweep_hw`

## Vulnerable Code
`main_board/src/optics/ir_camera_system/ir_camera_system_hw.c:191` — `ir_camera_system_set_focus_values_for_focus_sweep_hw()`

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

If the caller provides a buffer smaller than 400 bytes, `memcpy` will read beyond the bounds of the input buffer. Since the input buffer is often part of a larger, shared Protobuf message structure (`mcu_message` in `runner.c`), this allows an attacker to copy adjacent memory content (which may contain sensitive information) into the `global_focus_values` array.

## Attack Path
1. Attacker sends a `JetsonToMcu` message with `ir_eye_camera_focus_sweep_lens_values` payload.
2. The attacker provides only 1 focus value (2 bytes) in the `focus_values` field.
3. `runner_handle_new_can` decodes the message into the shared static `mcu_message` struct.
4. `handle_ir_eye_camera_focus_sweep_lens_values` calls `ir_camera_system_set_focus_values_for_focus_sweep` with a pointer to the decoded bytes.
5. `ir_camera_system_set_focus_values_for_focus_sweep_hw` executes `memcpy(global_focus_values, focus_values, 400)`.
6. 398 bytes of trailing data from the `mcu_message` struct or adjacent stack/static memory are copied into `global_focus_values`.
7. The leaked data can potentially be retrieved by the attacker via liquid lens telemetry logs or other system status messages that report current hardware settings.

## PoC
```bash
./run_poc.sh
# Expected output:
# [+] Memory layout simulation: sim struct at 0x7ffd51adcbe0
# [+] Sensitive data at 0x7ffd51adcbf4
# [+] Calling vulnerable function with focus_values pointer = 0x7ffd51adcbe0
# [+] Checking if sensitive data was leaked into global_focus_values...
# [!] PoC SUCCESS: Sensitive data leaked into global_focus_values array at offset 20!
# [!] Leaked string found: CONFIDENTIAL_PRIVATE_KEY_OR_TOKEN
```

## Impact
Information Leak. An attacker on the CAN bus can read up to 398 bytes of internal memory from the shared `mcu_message` buffer. This could include parts of previous messages, internal pointers, or stack data, potentially leading to the disclosure of sensitive state or aiding in further exploitation.

## Fix
Ensure `memcpy` only copies the amount of data actually received.

```c
<<<<<<< SEARCH
void
ir_camera_system_set_focus_values_for_focus_sweep_hw(int16_t *focus_values,
                                                     size_t num_focus_values)
{
    global_num_focus_values = num_focus_values;
    memcpy(global_focus_values, focus_values, sizeof(global_focus_values));
    use_focus_sweep_polynomial = false;
}
=======
void
ir_camera_system_set_focus_values_for_focus_sweep_hw(int16_t *focus_values,
                                                     size_t num_focus_values)
{
    global_num_focus_values = num_focus_values;
    memcpy(global_focus_values, focus_values, num_focus_values * sizeof(int16_t));
    use_focus_sweep_polynomial = false;
}
>>>>>>> REPLACE
```

## Status
CONFIRMED
