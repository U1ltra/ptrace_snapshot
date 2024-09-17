

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
