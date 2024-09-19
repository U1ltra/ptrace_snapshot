

```
ubuntu@ubuntu:~/Documents/testcases$ cat script.sh 

cat /proc/sys/kernel/yama/ptrace_scope
sudo sysctl -w kernel.yama.ptrace_scope=0

gcc -o ptrace_basic_test ptrace_basic_test.c
sudo ./ptrace_basic_test

#gcc -o ptrace_snapshot_test ptrace_snapshot_test.c
#sudo ./ptrace_snapshot_test

ubuntu@ubuntu:~/Documents/testcases$ bash script.sh 
0
kernel.yama.ptrace_scope = 0
Child process (PID = 18097) running...
Parent: Child stopped after attach. Testing ptrace...
Parent: Read word from child's stack (address ffffd31c0c20) = ffffd31c0d30
Parent: Wrote word to child's stack (address ffffd31c0c20) = 12345678
Child: Count = 0
Child: Count = 1
Child: Count = 2
Child: Count = 3
Child: Count = 4
Parent: Child exited with status 0.
```

before recompilation. simple call to ptrace snapshot
```
ubuntu@ubuntu:~/Documents/testcases$ gcc -o ptrace_snapshot_test ptrace_snapshot_test.c
ptrace_snapshot_test.c: In function \u2018main\u2019:
ptrace_snapshot_test.c:79:26: error: \u2018PTRACE_SNAPSHOT\u2019 undeclared (first use in this function)
   79 |             ret = ptrace(PTRACE_SNAPSHOT, child_pid, target_addr, SNAPSHOT_SIZE);
      |                          ^~~~~~~~~~~~~~~
ptrace_snapshot_test.c:79:26: note: each undeclared identifier is reported only once for each function it appears in
```

recompile the kernel
```
make -j$(nproc) 2>&1 | tee build.log
sudo make modules_install
sudo make install
sudo update-grub
sudo reboot
uname -r
```

```
sudo mv /boot/*5.10.224 ~/Documents/boot/<number>
sudo vim /etc/default/grub

GRUB_TIMEOUT_STYLE=hidden -> GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=10

sudo update-grub # update to reflect the change
```
fuck this is just sometimes work while sometimes does not.
sometimes shift works, sometimes esc works, sometimes nothing works. my god

OK, 确实是sched.h的问题。改回原来的code之后compile就work了

把 snapshot_list 和 limit size declare 的位置移动了一下。
再compile之后就可以boot modified之后的 linux 5.10.224  了。
重新跑了一下basic test program，结果正常
```
0
kernel.yama.ptrace_scope = 0
Child process (PID = 2475) running...
Parent: Child stopped after attach. Testing ptrace...
Parent: Read word from child's stack (address fffff35a3860) = fffff35a3970
Parent: Wrote word to child's stack (address fffff35a3860) = 12345678
Child: Count = 0
Child: Count = 1
Child: Count = 2
Child: Count = 3
Child: Count = 4
Parent: Child exited with status 0.
```

```
sudo make headers_install
sudo make headers_install INSTALL_HDR_PATH=/usr
```

```
gcc -g -o ptrace_snapshot_test ptrace_snapshot_test.c # -g for list command debugging in gdb
```

The output of printk() goes to the kernel log buffer, which can be viewed with the dmesg command or in /var/log/kern.log. 

Clearing the kernel ring buffer with dmesg -C only affects the current session's view of the kernel logs, and the logs will still be stored in the system log files like /var/log/kern.log if you have persistent logging enabled.
```
sudo dmesg | tail -n 50

sudo dmesg -C # clear the log for the current session
```

testcase
16^5 address
64 bytes

```
cat /proc/self/maps
```

Random invalid memory addresses
```
ubuntu@ubuntu:~/Documents/testcases$ bash script.sh 
1
[sudo] password for ubuntu: 
kernel.yama.ptrace_scope = 0
ptrace_snapshot_test.c:14:9: note: \u2018#pragma message: ptrace.h path: ptrace_snapshot_test.c\u2019
   14 | #pragma message "ptrace.h path: " __FILE__
      |         ^~~~~~~
Child process (PID = 2006) running...
Parent: Child stopped, now attaching...
Enter the target address of the memory region to snapshot: 0xffffbf47b000
Parent: Child stopped after attach. Taking snapshot...
ptrace SNAPSHOT: Bad address
Child: Address of test memory = 0xaaaaf560c6b0
ubuntu@ubuntu:~/Documents/testcases$ sudo dmesg | tail -n 30
[   24.561985] rfkill: input handler disabled
[   25.070585] input: spice vdagent tablet as /devices/virtual/input/input5
[   40.279928] --- ptrace syscall ---
[   40.280193] Reached line 1430 in function __do_sys_ptrace
[   40.280529] ptrace syscall called with:
[   40.280530]   request = 0
[   40.280530]   pid     = 0
[   40.280530]   addr    = 0
[   40.280530]   data    = 0
[   40.280531] --- ptrace_traceme ---
[   40.280532] --- Initializing snapshot list for PID 2006 ---
[   40.280532] Reached line 55 in function initialize_snapshot_list
[   82.248585] --- ptrace syscall ---
[   82.248915] Reached line 1430 in function __do_sys_ptrace
[   82.249016] ptrace syscall called with:
[   82.249017]   request = 20481
[   82.249017]   pid     = 2006
[   82.249017]   addr    = ffffbf47b000
[   82.249017]   data    = 40
[   82.249020] --- ptrace_request ---
[   82.249079] Reached line 1077 in function ptrace_request
[   82.249172] request: 20481
[   82.249219] addr: ffffbf47b000
[   82.249272] data: 40
[   82.249311] --- PTRACE_SNAPSHOT ---
[   82.249372] Reached line 1094 in function ptrace_request
[   82.249459] length: 40
[   82.249498] child->total_snapshot_size: 0
[   82.249564] vma->vm_start: ffffe63ca000
[   82.249626] vma->vm_end: ffffe63eb000
```

```
ubuntu@ubuntu:~/Documents/testcases$ bash script.sh 
0
kernel.yama.ptrace_scope = 0
ptrace_snapshot_test.c:14:9: note: \u2018#pragma message: ptrace.h path: ptrace_snapshot_test.c\u2019
   14 | #pragma message "ptrace.h path: " __FILE__
      |         ^~~~~~~
Child process (PID = 2201) running...
Parent: Child stopped, now attaching...
Enter the target address of the memory region to snapshot: 0xffffe63ca000
Parent: Child stopped after attach. Taking snapshot...
Child: Address of test memory = 0xaaaabd7eb6b0
script.sh: line 9:  2198 Segmentation fault      (core dumped) sudo ./ptrace_snapshot_test

ubuntu@ubuntu:~/Documents/testcases$ sudo dmesg | tail -n 100
[   25.070585] input: spice vdagent tablet as /devices/virtual/input/input5
[   40.279928] --- ptrace syscall ---
[   40.280193] Reached line 1430 in function __do_sys_ptrace
[   40.280529] ptrace syscall called with:
[   40.280530]   request = 0
[   40.280530]   pid     = 0
[   40.280530]   addr    = 0
[   40.280530]   data    = 0
[   40.280531] --- ptrace_traceme ---
[   40.280532] --- Initializing snapshot list for PID 2006 ---
[   40.280532] Reached line 55 in function initialize_snapshot_list
[   82.248585] --- ptrace syscall ---
[   82.248915] Reached line 1430 in function __do_sys_ptrace
[   82.249016] ptrace syscall called with:
[   82.249017]   request = 20481
[   82.249017]   pid     = 2006
[   82.249017]   addr    = ffffbf47b000
[   82.249017]   data    = 40
[   82.249020] --- ptrace_request ---
[   82.249079] Reached line 1077 in function ptrace_request
[   82.249172] request: 20481
[   82.249219] addr: ffffbf47b000
[   82.249272] data: 40
[   82.249311] --- PTRACE_SNAPSHOT ---
[   82.249372] Reached line 1094 in function ptrace_request
[   82.249459] length: 40
[   82.249498] child->total_snapshot_size: 0
[   82.249564] vma->vm_start: ffffe63ca000
[   82.249626] vma->vm_end: ffffe63eb000
[  153.091301] --- ptrace syscall ---
[  153.091586] Reached line 1430 in function __do_sys_ptrace
[  153.091936] ptrace syscall called with:
[  153.091937]   request = 0
[  153.091937]   pid     = 0
[  153.091937]   addr    = 0
[  153.091937]   data    = 0
[  153.091938] --- ptrace_traceme ---
[  153.091939] --- Initializing snapshot list for PID 2201 ---
[  153.091939] Reached line 55 in function initialize_snapshot_list
[  158.088896] --- ptrace syscall ---
[  158.089205] Reached line 1430 in function __do_sys_ptrace
[  158.091125] ptrace syscall called with:
[  158.091128]   request = 20481
[  158.091128]   pid     = 2201
[  158.091128]   addr    = ffffe63ca000
[  158.091128]   data    = 40
[  158.091135] --- ptrace_request ---
[  158.091281] Reached line 1077 in function ptrace_request
[  158.091660] request: 20481
[  158.091802] addr: ffffe63ca000
[  158.091944] data: 40
[  158.092049] --- PTRACE_SNAPSHOT ---
[  158.092216] Reached line 1094 in function ptrace_request
[  158.092470] length: 40
[  158.092587] child->total_snapshot_size: 0
[  158.092846] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[  158.093162] Mem abort info:
[  158.093291]   ESR = 0x96000004
[  158.093346]   EC = 0x25: DABT (current EL), IL = 32 bits
[  158.093432]   SET = 0, FnV = 0
[  158.093481]   EA = 0, S1PTW = 0
[  158.093535] Data abort info:
[  158.093584]   ISV = 0, ISS = 0x00000004
[  158.093789]   CM = 0, WnR = 0
[  158.093846] user pgtable: 4k pages, 48-bit VAs, pgdp=0000000067c0c000
[  158.094054] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000
[  158.094301] Internal error: Oops: 0000000096000004 [#1] SMP
[  158.094543] Modules linked in: snd_hda_codec_generic ledtrig_audio snd_hda_intel snd_intel_dspcfg nls_iso8859_1 snd_hda_codec snd_hda_core snd_hwdep snd_pcm snd_seq_midi snd_seq_midi_event snd_rawmidi snd_seq snd_seq_device snd_timer uas joydev input_leds usb_storage snd soundcore qemu_fw_cfg sch_fq_codel dm_multipath scsi_dh_rdac scsi_dh_emc scsi_dh_alua binfmt_misc efi_pstore ip_tables x_tables autofs4 btrfs blake2b_generic raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx xor xor_neon hid_generic usbhid hid raid6_pq libcrc32c raid1 raid0 multipath linear 9pnet_virtio 9p 9pnet fscache virtio_input crct10dif_ce ghash_ce sha3_ce sha3_generic sha512_ce sha512_arm64 sha2_ce virtio_gpu virtio_dma_buf sha256_arm64 drm_kms_helper syscopyarea sysfillrect sysimgblt fb_sys_fops sha1_ce cec rc_core virtio_net net_failover virtio_blk drm virtio_rng xhci_pci failover xhci_pci_renesas aes_neon_bs aes_neon_blk aes_ce_blk crypto_simd cryptd aes_ce_cipher
[  158.098167] CPU: 4 PID: 2200 Comm: ptrace_snapshot Not tainted 5.10.224 #18
[  158.098167] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/2015
[  158.098168] pstate: 80400005 (Nzcv daif +PAN -UAO -TCO BTYPE=--)
[  158.098172] pc : ptrace_request+0x2a8/0x984
[  158.098173] lr : ptrace_request+0x29c/0x984
[  158.098173] sp : ffff8000118c3d40
[  158.098173] x29: ffff8000118c3d40 x28: ffff72c805208f80 
[  158.098174] x27: 0000000000000000 x26: 0000000000000000 
[  158.098175] x25: ffffc55ac14b60a0 x24: ffffc55ac14b6270 
[  158.098177] x23: 0000ffffe63ca000 x22: ffff72c803a89328 
[  158.098177] x21: 0000000000000040 x20: ffff72c8fd432e80 
[  158.098178] x19: 0000000000000000 x18: 0000000000000000 
[  158.098178] x17: 0000000000000000 x16: 0000000000000000 
[  158.098179] x15: 0000000000000000 x14: 0000000000000000 
[  158.098181] x13: ffff8000118c39e0 x12: 000000000000000f 
[  158.098181] x11: 0000000000000010 x10: 0000000000000004 
[  158.098182] x9 : ffffc55ac02b13bc x8 : 616e735f6c61746f 
[  158.098182] x7 : 0000000000000001 x6 : 0000000000000001 
[  158.098183] x5 : 0000000000000000 x4 : ffff72c8ff604a48 
[  158.101849] x3 : ffff72c8fd433658 x2 : 0000000000000000 
[  158.102892] x1 : 0000ffffc9172000 x0 : ffffc55ac14b6298 
[  158.103172] Call trace:
[  158.103301]  ptrace_request+0x2a8/0x984
[  158.103548]  arch_ptrace+0x24/0x4c
[  158.103752]  __arm64_sys_ptrace+0x118/0x1c8
[  158.104014]  el0_svc_common.constprop.0+0x88/0x250
[  158.104362]  do_el0_svc+0x30/0xb0
[  158.104554]  el0_svc+0x20/0x30
[  158.104856]  el0_sync_handler+0xa4/0x130
[  158.105078]  el0_sync+0x184/0x1c0
[  158.105169] Code: 97cc186f aa0003f3 f0002840 910a6000 (f9400261) 
[  158.105334] ---[ end trace 1fedd876322f7b9a ]---
```

Worked!
```
ubuntu@ubuntu:~/Documents/testcases$ bash script.sh 
0
kernel.yama.ptrace_scope = 0
Child process (PID = 2400) running...
Parent: Child stopped, now attaching...
Memory map of child process 2400:
aaaac3080000-aaaac3082000 r-xp 00000000 fd:00 2097157                    /home/ubuntu/Documents/testcases/ptrace_snapshot_test
aaaac3091000-aaaac3092000 r--p 00001000 fd:00 2097157                    /home/ubuntu/Documents/testcases/ptrace_snapshot_test
aaaac3092000-aaaac3093000 rw-p 00002000 fd:00 2097157                    /home/ubuntu/Documents/testcases/ptrace_snapshot_test
aaaae5bdf000-aaaae5c00000 rw-p 00000000 00:00 0                          [heap]
ffff95a00000-ffff95b88000 r-xp 00000000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff95b88000-ffff95b97000 ---p 00188000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff95b97000-ffff95b9b000 r--p 00187000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff95b9b000-ffff95b9d000 rw-p 0018b000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff95b9d000-ffff95ba9000 rw-p 00000000 00:00 0 
ffff95bc5000-ffff95bf0000 r-xp 00000000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffff95bfa000-ffff95bfc000 rw-p 00000000 00:00 0 
ffff95bfc000-ffff95bfe000 r--p 00000000 00:00 0                          [vvar]
ffff95bfe000-ffff95bff000 r-xp 00000000 00:00 0                          [vdso]
ffff95bff000-ffff95c01000 r--p 0002a000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffff95c01000-ffff95c03000 rw-p 0002c000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffcd364000-ffffcd385000 rw-p 00000000 00:00 0                          [stack]
Enter the target address of the memory region to snapshot: 0xffffcd365000        
Parent: Child stopped after attach. Taking snapshot...
Parent: Snapshot 1 taken successfully.
Parent: Detached from child.
Child: Address of test memory = 0xaaaae5bdf6b0

ubuntu@ubuntu:~/Documents/testcases$ sudo dmesg | tail -n 50
[  797.685360] --- ptrace syscall ---
[  797.685512] Reached line 1430 in function __do_sys_ptrace
[  797.685620] ptrace syscall called with:
[  797.685696]   request = 0
[  797.685747]   pid     = 0
[  797.685817]   addr    = 0
[  797.685869]   data    = 0
[  797.685922] --- ptrace_traceme ---
[  797.685991] --- Initializing snapshot list for PID 2400 ---
[  797.686101] Reached line 55 in function initialize_snapshot_list
[  820.028194] --- ptrace syscall ---
[  820.028529] Reached line 1430 in function __do_sys_ptrace
[  820.028685] ptrace syscall called with:
[  820.028795]   request = 20481
[  820.029046]   pid     = 2400
[  820.029134]   addr    = ffffcd365000
[  820.029237]   data    = 40
[  820.029326] --- ptrace_request ---
[  820.029596] Reached line 1077 in function ptrace_request
[  820.029979] request: 20481
[  820.030175] addr: ffffcd365000
[  820.030264] data: 40
[  820.030329] --- PTRACE_SNAPSHOT ---
[  820.030429] Reached line 1094 in function ptrace_request
[  820.030589] length: 40
[  820.030784] child->total_snapshot_size: 0
[  820.031109] vma->vm_start: ffffcd364000
[  820.031509] vma->vm_end: ffffcd385000
[  820.031896] vma->vm_flags: 200100173
[  820.032272] vma->vm_flags & VM_WRITE: 2
[  820.033093] Memory region is valid and writable.
[  820.033666] snap kmalloc
[  820.033818] snap->data kmalloc
[  820.034050] copied: 40
[  820.034363] snap->data copied
[  820.034652] snap->length: 40
[  820.034853] snap->addr: ffffcd365000
[  820.035651] snap->list update
[  820.036333] child->total_snapshot_size: 40
[  820.037779] --- ptrace syscall ---
[  820.038472] Reached line 1430 in function __do_sys_ptrace
[  820.039093] ptrace syscall called with:
[  820.039864]   request = 17
[  820.040367]   pid     = 2400
[  820.041189]   addr    = 0
[  820.041530]   data    = 0
[  820.041705] --- ptrace_request ---
[  820.041875] Reached line 1077 in function ptrace_request
[  820.042101] request: 17
[  820.042834] addr: 0
[  820.044278] data: 0
```


snapshot 基本成功
```
ubuntu@ubuntu:~/Documents/testcases$ bash script.sh 
0
kernel.yama.ptrace_scope = 0
Child process (PID = 2213) running...
Parent: Child stopped, now attaching...
Memory map of child process 2213:
aaaadbd70000-aaaadbd72000 r-xp 00000000 fd:00 2097155                    /home/ubuntu/Documents/testcases/ptrace_snapshot_test
aaaadbd81000-aaaadbd82000 r--p 00001000 fd:00 2097155                    /home/ubuntu/Documents/testcases/ptrace_snapshot_test
aaaadbd82000-aaaadbd83000 rw-p 00002000 fd:00 2097155                    /home/ubuntu/Documents/testcases/ptrace_snapshot_test
aaab0fd3b000-aaab0fd5c000 rw-p 00000000 00:00 0                          [heap]
ffffa84c0000-ffffa8648000 r-xp 00000000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffa8648000-ffffa8657000 ---p 00188000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffa8657000-ffffa865b000 r--p 00187000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffa865b000-ffffa865d000 rw-p 0018b000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffa865d000-ffffa8669000 rw-p 00000000 00:00 0 
ffffa867a000-ffffa86a5000 r-xp 00000000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffa86af000-ffffa86b1000 rw-p 00000000 00:00 0 
ffffa86b1000-ffffa86b3000 r--p 00000000 00:00 0                          [vvar]
ffffa86b3000-ffffa86b4000 r-xp 00000000 00:00 0                          [vdso]
ffffa86b4000-ffffa86b6000 r--p 0002a000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffa86b6000-ffffa86b8000 rw-p 0002c000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffeb308000-ffffeb329000 rw-p 00000000 00:00 0                          [stack]
Parent: Enter the target address of the memory region to poke: 0xffffeb309008
Parent: Wrote word to child's stack (address ffffeb309008) = 12345678
Enter the target address of the memory region to snapshot: 0xffffeb309000
Parent: Child stopped after attach. Taking snapshot...
Parent: Snapshot 1 taken successfully.
Parent: Detached from child.
Child: Address of test memory = 0xaaab0fd3b6b0

ubuntu@ubuntu:~/Documents/testcases$ sudo dmesg | tail -n 200
[  103.596112] --- ptrace_traceme ---
[  103.596113] --- Initializing snapshot list for PID 2061 ---
[  103.596113] Reached line 55 in function initialize_snapshot_list
[  278.164715] --- ptrace syscall ---
[  278.164990] Reached line 1449 in function __do_sys_ptrace
[  278.165391] ptrace syscall called with:
[  278.165391]   request = 0
[  278.165391]   pid     = 0
[  278.165392]   addr    = 0
[  278.165392]   data    = 0
[  278.165392] --- ptrace_traceme ---
[  278.165393] --- Initializing snapshot list for PID 2213 ---
[  278.165393] Reached line 55 in function initialize_snapshot_list
[  305.013102] --- ptrace syscall ---
[  305.013397] Reached line 1449 in function __do_sys_ptrace
[  305.013494] ptrace syscall called with:
[  305.013495]   request = 5
[  305.013495]   pid     = 2213
[  305.013495]   addr    = ffffeb309008
[  305.013495]   data    = 12345678
[  305.013497] --- ptrace_request ---
[  305.013554] Reached line 1079 in function ptrace_request
[  305.013642] request: 5
[  305.013682] addr: ffffeb309008
[  305.013733] data: 12345678
[  305.013778] --- generic_ptrace_pokedata ---
[  305.013848] Reached line 1518 in function generic_ptrace_pokedata
[  305.013949] addr: ffffeb309008
[  305.014000] data: 12345678
[  314.457249] --- ptrace syscall ---
[  314.457422] Reached line 1449 in function __do_sys_ptrace
[  314.457553] ptrace syscall called with:
[  314.457554]   request = 20481
[  314.457554]   pid     = 2213
[  314.457554]   addr    = ffffeb309000
[  314.457555]   data    = 40
[  314.457557] --- ptrace_request ---
[  314.457620] Reached line 1079 in function ptrace_request
[  314.457715] request: 20481
[  314.457764] addr: ffffeb309000
[  314.457820] data: 40
[  314.457859] --- PTRACE_SNAPSHOT ---
[  314.457917] Reached line 1096 in function ptrace_request
[  314.458004] length: 40
[  314.458044] child->total_snapshot_size: 0
[  314.458111] vma->vm_start: ffffeb308000
[  314.458175] vma->vm_end: ffffeb329000
[  314.458235] vma->vm_flags: 200100173
[  314.458294] vma->vm_flags & VM_WRITE: 2
[  314.458358] Memory region is valid and writable.
[  314.458434] snap kmalloc
[  314.458476] snap->data kmalloc
[  314.458532] copied: 40
[  314.458571] snap->data copied
[  314.458620] snap->length: 40
[  314.458668] snap->addr: ffffeb309000
[  314.458728] snap->list update
[  314.458777] child->total_snapshot_size: 40
[  314.458845] snap->data[0]: 0
[  314.458893] snap->data[1]: 0
[  314.458940] snap->data[2]: 0
[  314.458988] snap->data[3]: 0
[  314.459060] snap->data[4]: 0
[  314.459111] snap->data[5]: 0
[  314.459163] snap->data[6]: 0
[  314.459214] snap->data[7]: 0
[  314.459265] snap->data[8]: 78
[  314.459318] snap->data[9]: 56
[  314.459371] snap->data[10]: 34
[  314.459424] snap->data[11]: 12
...
[  314.465688] tmp->length: 40
[  314.465828] tmp->addr: ffffeb309000
[  314.467223] tmp->data[0]: 0
[  314.467583] tmp->data[1]: 0
[  314.467874] tmp->data[2]: 0
[  314.468414] tmp->data[3]: 0
[  314.468869] tmp->data[4]: 0
[  314.469419] tmp->data[5]: 0
[  314.469471] tmp->data[6]: 0
[  314.469522] tmp->data[7]: 0
[  314.469574] tmp->data[8]: 78
[  314.469627] tmp->data[9]: 56
[  314.469680] tmp->data[10]: 34
[  314.469734] tmp->data[11]: 12
...
[  314.478020] --- ptrace syscall ---
[  314.478489] Reached line 1449 in function __do_sys_ptrace
[  314.478901] ptrace syscall called with:
[  314.478902]   request = 17
[  314.478902]   pid     = 2213
[  314.478902]   addr    = 0
[  314.478902]   data    = 0
[  314.478904] --- ptrace_request ---
[  314.479105] Reached line 1079 in function ptrace_request
[  314.479943] request: 17
[  314.480248] addr: 0
[  314.480573] data: 0
```

restore works
```
ubuntu@ubuntu:~/Documents/testcases$ bash script.sh 
1
[sudo] password for ubuntu: 
kernel.yama.ptrace_scope = 0
Child process (PID = 2219) running...
Parent: Child stopped, now attaching...
Memory map of child process 2219:
aaaac4cd0000-aaaac4cd2000 r-xp 00000000 fd:00 2097156                    /home/ubuntu/Documents/testcases/ptrace_restore_test
aaaac4ce1000-aaaac4ce2000 r--p 00001000 fd:00 2097156                    /home/ubuntu/Documents/testcases/ptrace_restore_test
aaaac4ce2000-aaaac4ce3000 rw-p 00002000 fd:00 2097156                    /home/ubuntu/Documents/testcases/ptrace_restore_test
aaaae8ab7000-aaaae8ad8000 rw-p 00000000 00:00 0                          [heap]
ffff9c440000-ffff9c5c8000 r-xp 00000000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff9c5c8000-ffff9c5d7000 ---p 00188000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff9c5d7000-ffff9c5db000 r--p 00187000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff9c5db000-ffff9c5dd000 rw-p 0018b000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffff9c5dd000-ffff9c5e9000 rw-p 00000000 00:00 0 
ffff9c601000-ffff9c62c000 r-xp 00000000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffff9c636000-ffff9c638000 rw-p 00000000 00:00 0 
ffff9c638000-ffff9c63a000 r--p 00000000 00:00 0                          [vvar]
ffff9c63a000-ffff9c63b000 r-xp 00000000 00:00 0                          [vdso]
ffff9c63b000-ffff9c63d000 r--p 0002a000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffff9c63d000-ffff9c63f000 rw-p 0002c000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffec55e000-ffffec57f000 rw-p 00000000 00:00 0                          [stack]
Parent: Enter the target address of the memory region to snapshot: ffffec55f000
Parent: Taking snapshot of memory at address 0xffffec55f000...
Parent: Snapshot taken successfully.
Parent: Modifying child's memory at address 0xffffec55f000...
Parent: Child's memory modified.
Parent: Verifying modified memory...
Memory at 0xffffec55f000: 0xaaaaaaaaaaaaaaaa
Memory at 0xffffec55f008: 0xaaaaaaaaaaaaaaaa
Memory at 0xffffec55f010: 0xaaaaaaaaaaaaaaaa
Memory at 0xffffec55f018: 0xaaaaaaaaaaaaaaaa
Memory at 0xffffec55f020: 0xaaaaaaaaaaaaaaaa
Memory at 0xffffec55f028: 0xaaaaaaaaaaaaaaaa
Memory at 0xffffec55f030: 0xaaaaaaaaaaaaaaaa
Memory at 0xffffec55f038: 0xaaaaaaaaaaaaaaaa
Parent: Restoring snapshot at address 0xffffec55f000...
Parent: Snapshot restored successfully.
Parent: Verifying restored memory...
Memory at 0xffffec55f000: 0x0
Memory at 0xffffec55f008: 0x0
Memory at 0xffffec55f010: 0x0
Memory at 0xffffec55f018: 0x0
Memory at 0xffffec55f020: 0x0
Memory at 0xffffec55f028: 0x0
Memory at 0xffffec55f030: 0x0
Memory at 0xffffec55f038: 0x0
Parent: Detached from child.
Child: Address of test_memory = 0xaaaae8ab76b0
```

PTRACE_GETSNAPSHOT working
```
ubuntu@ubuntu:~/Documents/testcases$ bash script.sh 
0
kernel.yama.ptrace_scope = 0
Child process (PID = 2513) running...
Parent: Child stopped, now attaching...
Memory map of child process 2513:
aaaab4ef0000-aaaab4ef2000 r-xp 00000000 fd:00 2097162                    /home/ubuntu/Documents/testcases/ptrace_get_test
aaaab4f01000-aaaab4f02000 r--p 00001000 fd:00 2097162                    /home/ubuntu/Documents/testcases/ptrace_get_test
aaaab4f02000-aaaab4f03000 rw-p 00002000 fd:00 2097162                    /home/ubuntu/Documents/testcases/ptrace_get_test
aaaaf1cce000-aaaaf1cef000 rw-p 00000000 00:00 0                          [heap]
ffffbaad0000-ffffbac58000 r-xp 00000000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffbac58000-ffffbac67000 ---p 00188000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffbac67000-ffffbac6b000 r--p 00187000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffbac6b000-ffffbac6d000 rw-p 0018b000 fd:00 450100                     /usr/lib/aarch64-linux-gnu/libc.so.6
ffffbac6d000-ffffbac79000 rw-p 00000000 00:00 0 
ffffbac96000-ffffbacc1000 r-xp 00000000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffbaccb000-ffffbaccd000 rw-p 00000000 00:00 0 
ffffbaccd000-ffffbaccf000 r--p 00000000 00:00 0                          [vvar]
ffffbaccf000-ffffbacd0000 r-xp 00000000 00:00 0                          [vdso]
ffffbacd0000-ffffbacd2000 r--p 0002a000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffbacd2000-ffffbacd4000 rw-p 0002c000 fd:00 450039                     /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
ffffc7437000-ffffc7458000 rw-p 00000000 00:00 0                          [stack]
Enter the target address of the memory region to snapshot: 0xffffc7438000
Parent: Writing values to the child's memory using PTRACE_POKEDATA...
Parent: Wrote deadbeef to child's memory at address ffffc7438000
Parent: Wrote deadbef7 to child's memory at address ffffc7438008
Parent: Wrote deadbeff to child's memory at address ffffc7438010
Parent: Wrote deadbf07 to child's memory at address ffffc7438018
Parent: Wrote deadbf0f to child's memory at address ffffc7438020
Parent: Wrote deadbf17 to child's memory at address ffffc7438028
Parent: Wrote deadbf1f to child's memory at address ffffc7438030
Parent: Wrote deadbf27 to child's memory at address ffffc7438038
Parent: Child stopped after attach. Taking snapshot...
Parent: Snapshot taken successfully.
Parent: Retrieving snapshot...
Parent: Snapshot data retrieved:
ef be ad de 00 00 00 00 f7 be ad de 00 00 00 00 
ff be ad de 00 00 00 00 07 bf ad de 00 00 00 00 
0f bf ad de 00 00 00 00 17 bf ad de 00 00 00 00 
1f bf ad de 00 00 00 00 27 bf ad de 00 00 00 00 

Parent: Detached from child.
Child: Address of test memory = 0xaaaaf1cce6b0
```