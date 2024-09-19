cat /proc/sys/kernel/yama/ptrace_scope
sudo sysctl -w kernel.yama.ptrace_scope=0

echo -e "\n<<< basic >>>"
gcc -g -o ptrace_basic_test ptrace_basic_test.c
sudo ./ptrace_basic_test

echo -e "\n<<< snapshot >>>"
gcc -g -o ptrace_snapshot_test ptrace_snapshot_test.c # enable debugging
sudo ./ptrace_snapshot_test

echo -e "\n<<< restore >>>"
gcc -g -o ptrace_restore_test ptrace_restore_test.c # enable debugging
sudo ./ptrace_restore_test

echo -e "\n<<< get >>>"
gcc -g -o ptrace_get_test ptrace_get_test.c # enable debugging
sudo ./ptrace_get_test

echo -e "\n<<< test1 >>>"
gcc -g -o ptrace_test1 ptrace_test1.c # enable debugging
sudo ./ptrace_test1

echo -e "\n<<< test2 >>>"
gcc -g -o ptrace_test2 ptrace_test2.c # enable debugging
sudo ./ptrace_test2