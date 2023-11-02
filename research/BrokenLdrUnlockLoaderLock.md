# Broken LdrUnlockLoaderLock

This is the analysis and following proofs showing that a developer at Microsoft intentionally broke the `LdrUnlockLoaderLock` NTDLL export.

## Analysis

Here's the the `Cookie` validation code in `LdrUnlockLoaderLock`:

```asm
mov     rax, 1000000000000000h

; If Cookie >= 0x1000000000000000 (that's 16 hex digits) then error
; jae = Jump if greater than or equal to
cmp     rdx, rax                                         ; Cookie is this function's second argument so it's stored in RDX
jae     ntdll!LdrUnlockLoaderLock+0x49370 (7ff94e0d7330) ; Jump to error-handling code

mov     rax, qword ptr gs:[30h]                          ; Get Thread Environment Block (TEB) address

shr     rdx, 30h                                         ; Shift cookie value right logical 0x30
                                                         ; For example, 0xffffffffffffffff (16 digits) >> 0x30 = 0xffff

mov     eax, dword ptr [rax+48h]                         ; Get current thread ID from TEB
                                                         ; ID is a DWORD in size (32-bits; or 8 hex digits)
                                                         ; Usually though, an ID is at most 4 hex digits (2 bytes)
                                                         ; Although, it could have a leading zero effectively making it less

; If Cookie ^ (xor) threadId != 0xfff then error
; jne = Jump if not equal
xor     rdx, rax
test    rdx, 0FFFh
jne     ntdll!LdrUnlockLoaderLock+0x49370 (7ff94e0d7330) ; Jump to error-handling code
```

Based on this analysis, it's impossible to provide a 4 hex digit or greater thread ID as the `LdrUnlockLoaderLock` `Cookie` because the `cmp` check will error if the value we send in is 16 hex digits. However, the `Cookie` needs that many hex digits so the `shr` keeps at least 4 hex digits for the following XOR condtion against the thread ID. To pass the XOR condition, we need our 4 digit thread ID to be `xor`'d by another 4 hex digit value which could only then possibly be equal to `0x0fff`.

## Python Bruteforcer Proof

To be 100% sure, I proved this with a simple Python bruteforcer script:

```python
cookie = 0x0
while True:
# Example thread ID is 0x29b0 (real thread ID I got)
if cookie ^ 0x29b0 == 0xfff:
    print(hex(cookie))
cookie += 1
```

Output: `0x264f`

So, 0x264f ^ 0x29b0 = 0xfff.

But, it's impossible to make a Cookie the size of `0x264f` without jumping to error code early for being too big or later because too much get's shifted off then causing the `xor` to not equal `0xfff`.

The only way possible for `LdrUnlockLoaderLock` to unlock loader lock is if the thread ID happens to be generated with a leading zero (e.g. 0a85) because then our cookie is effectively only 3 hex digits. This would allow us to fulfill both conditions: Be lower than the max value in the `cmp` check **and** keep enough hex digits so we can survive the shift right to pass the following `xor` check.

## Simple Proof

As a simple proof, the max cookie value we can provide without triggering the jump into error-handling code is:

```
0x0fffffffffffffff
```


This is because it's one less than:

```
0x1000000000000000
```

Shifting the max cookie value we can provide to the right 0x30 gives us a `Cookie` value of:
  - In Python: `hex(0x0fffffffffffffff >> 0x30)`

```
0xfff
```

There you have it, our `Cookie` only has 3 controllable hex digits. Therefore, it's impossible to pass the XOR check that proceeds for a 4 hex digit or greater thread ID.
