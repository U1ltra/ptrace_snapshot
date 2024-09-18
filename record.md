

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