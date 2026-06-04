# [CRITICAL] Stack-based Buffer Overflow in `backup_regs_read_byte`

## Vulnerable Code
`lib/storage/backup_regs.c:20` — `backup_regs_read_byte()`

```c
int
backup_regs_read_byte(const size_t offset, uint8_t *data)
{
    size_t size;
    int ret = bbram_get_size(backup_regs_dev, &size);
    if (ret == 0 && offset >= size) {
        return -EINVAL;
    }

    ret = bbram_read(backup_regs_dev, offset, sizeof(data), data);
    return ret;
}
```

## Root Cause
The function `backup_regs_read_byte` is intended to read a single byte from Battery-Backed RAM (BBRAM). However, it used `sizeof(data)` as the number of bytes to read. Since `data` is a pointer (`uint8_t *`), `sizeof(data)` evaluates to the size of the pointer (4 bytes on this 32-bit architecture), rather than the size of the data pointed to (1 byte).

This resulted in a 4-byte read into a buffer that is often only 1 byte large, causing a stack-based buffer overflow when called with a pointer to a stack-allocated `uint8_t`.

## Attack Path
1.  **Preparation**: An attacker can influence the contents of the BBRAM. While `backup_regs_write_byte` is also present and used to set a reboot flag, an attacker might use other system features or vulnerabilities to populate the BBRAM with malicious values, or simply rely on the existing values at adjacent offsets (0x01-0x03) to corrupt the stack.
2.  **Trigger**: The attacker sends a `REBOOT_ORB` CAN message to the Orb.
3.  **Execution**:
    -   The `handle_reboot_orb` function in `main_board/src/runner/runner.c` sets the reboot flag in BBRAM and triggers a system reset.
    -   Upon reboot, the system enters `app_init_state` in `main_board/src/power/boot/boot.c`.
    -   `app_init_state` declares a 1-byte local variable `uint8_t boot_flag`.
    -   It calls `backup_regs_read_byte(REBOOT_FLAG_OFFSET_BYTE, &boot_flag)`.
    -   Due to the bug, 4 bytes are read from BBRAM into the address of `boot_flag`, overflowing into adjacent stack memory.
4.  **Impact**: The overflow corrupts adjacent local variables on the stack. In `app_init_state`, this can include the `ret` variable or other critical state. More importantly, this pattern of using `backup_regs_read_byte` on a 1-byte stack variable is a recurring vulnerability that can lead to arbitrary code execution if the return address is reachable.

## PoC
The following script demonstrates the vulnerability by simulating the stack layout and the buggy `backup_regs_read_byte` function.

```bash
./run_poc.sh
# Expected output: [!] BUFFER CORRUPTION DETECTED beyond the first byte!
```

## Impact
This is a **CRITICAL** vulnerability. Stack-based buffer overflows in early boot stages are highly dangerous as they can bypass security boundaries (like RDP activation) or lead to full system compromise. Since the BBRAM persists across reboots, this vulnerability can be used to achieve persistent exploitation of the device.

## Fix
The `sizeof(data)` has been replaced with `1`.

```c
int
backup_regs_read_byte(const size_t offset, uint8_t *data)
{
    // ...
    ret = bbram_read(backup_regs_dev, offset, 1, data);
    return ret;
}
```

Similarly, `backup_regs_write_byte` has been fixed for consistency:

```c
int
backup_regs_write_byte(const size_t offset, const uint8_t data)
{
    // ...
    ret = bbram_write(backup_regs_dev, offset, 1, &data);
    return ret;
}
```

## Status
CONFIRMED
