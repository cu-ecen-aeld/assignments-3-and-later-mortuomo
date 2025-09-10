# Kernel Oops by the Faulty module

## What is the Faulty module?
The Faulty module is a kernel module that creates a character device named `/dev/faulty`.
The write methods for this device tries to dereference a NULL pointer, causing a kernel oops.

## Example of the kernel oops
This output was printed on a QEMU virt AARCH64 board.

```
# echo "hello_world" > /dev/faulty
[   54.880027] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[   54.880651] Mem abort info:
[   54.880708]   ESR = 0x0000000096000044
[   54.880784]   EC = 0x25: DABT (current EL), IL = 32 bits
[   54.880859]   SET = 0, FnV = 0
[   54.880906]   EA = 0, S1PTW = 0
[   54.880953]   FSC = 0x04: level 0 translation fault
[   54.881026] Data abort info:
[   54.881071]   ISV = 0, ISS = 0x00000044, ISS2 = 0x00000000
[   54.881500]   CM = 0, WnR = 1, TnD = 0, TagAccess = 0
[   54.883333]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
[   54.883522] user pgtable: 4k pages, 48-bit VAs, pgdp=00000000437c5000
[   54.883616] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000
[   54.883852] Internal error: Oops: 0000000096000044 [#1] PREEMPT SMP
[   54.884051] Modules linked in: hello(O) faulty(O) scull(O) ipv6
[   54.884641] CPU: 0 PID: 151 Comm: sh Tainted: G           O       6.6.84 #1
[   54.884792] Hardware name: linux,dummy-virt (DT)
[   54.884968] pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[   54.885058] pc : faulty_write+0x8/0x10 [faulty]
[   54.885876] lr : vfs_write+0xc8/0x30c
[   54.886135] sp : ffff80008027bd20
[   54.886556] x29: ffff80008027bd80 x28: ffff3afd0218ad00 x27: 0000000000000000
[   54.886856] x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
[   54.887050] x23: 0000000000000000 x22: ffff80008027bdc0 x21: 0000aaaae8d039e0
[   54.887235] x20: ffff3afd02058b00 x19: 000000000000000c x18: 0000000000000000
[   54.887521] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
[   54.887722] x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
[   54.887914] x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
[   54.888156] x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
[   54.888373] x5 : 0000000000000000 x4 : ffffb38010657000 x3 : ffff80008027bdc0
[   54.888658] x2 : 000000000000000c x1 : 0000000000000000 x0 : 0000000000000000
[   54.888957] Call trace:
[   54.889148]  faulty_write+0x8/0x10 [faulty]
[   54.889449]  ksys_write+0x74/0x10c
[   54.889599]  __arm64_sys_write+0x1c/0x28
[   54.889754]  invoke_syscall+0x48/0x118
[   54.889895]  el0_svc_common.constprop.0+0x40/0xe0
[   54.890094]  do_el0_svc+0x1c/0x28
[   54.890191]  el0_svc+0x38/0xcc
[   54.890413]  el0t_64_sync_handler+0x100/0x12c
[   54.890541]  el0t_64_sync+0x190/0x194
[   54.890901] Code: ???????? ???????? d2800001 d2800000 (b900003f) 
[   54.891679] ---[ end trace 0000000000000000 ]---
```

## Relevant information about the oops
The first line indicates the nature of the oops, an attempt to dereference a NULL pointer:
> `Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000`

The instruction that caused the oops is reported as the value of the pc register at the time of the oops:
> `pc : faulty_write+0x8/0x10 [faulty]`
The oops happened when running the function faulty_write, in module [faulty], 0x8 bytes from the start of the function in the binary.

To figure out what the instruction was, the `faulty.ko` file has to be disassembled using `objdump`. In this case, the target did not have objdump, so the following command was run on the host machine using the objdump from the appropriate cross compiler toolchain.
```
$ aarch64-none-linux-gnu-objdump -d buildroot/output/build/ldd-dabb967100f47eb2b7a551adb2c72c5893c4b5c9/misc-modules/faulty.ko

buildroot/output/build/ldd-dabb967100f47eb2b7a551adb2c72c5893c4b5c9/misc-modules/faulty.ko:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000000000 <faulty_write>:
   0:	d2800001 	mov	x1, #0x0                   	// #0
   4:	d2800000 	mov	x0, #0x0                   	// #0
   8:	b900003f 	str	wzr, [x1]
   c:	d65f03c0 	ret

... other code in .text ...
```
We can see that the instruction at offset 0x8 tries to dereference the address in register x1, which is set to 0x0 on the first instruction.