#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>    // For struct user_regs_struct
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    pid_t child_pid;
    int status;
    long ret;
    unsigned long addr;
    unsigned long data;
    struct user_regs_struct regs;

    // Fork the child process
    child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        // Child process (tracee)
        printf("Child process (PID = %d) running...\n", getpid());

        // Allow the parent to trace this process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace TRACEME");
            exit(EXIT_FAILURE);
        }

        // Stop the child to allow the parent to attach
        raise(SIGSTOP);

        // Child's main logic (dummy)
        for (int i = 0; i < 5; i++) {
            printf("Child: Count = %d\n", i);
            sleep(1);
        }

        exit(EXIT_SUCCESS);
    } else {
        // Parent process (tracer)
        waitpid(child_pid, &status, 0); // Wait for child to stop

        if (WIFSTOPPED(status)) {
            printf("Parent: Child stopped, now attaching...\n");

            // Use PTRACE_ATTACH to attach to the child process
            if (ptrace(PTRACE_ATTACH, child_pid, NULL, NULL) == -1) {
                perror("ptrace ATTACH");
                exit(EXIT_FAILURE);
            }

            waitpid(child_pid, &status, 0); // Wait for child to stop again

            if (WIFSTOPPED(status)) {
                printf("Parent: Child stopped after attach. Testing ptrace...\n");

                // Get the child process's registers
                ret = ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                if (ret == -1) {
                    perror("ptrace GETREGS");
                    exit(EXIT_FAILURE);
                }
                printf("Parent: Original RIP = %llx\n", regs.rip);

                // Modify the child's instruction pointer (RIP)
                regs.rip += 2; // Increment RIP by 2 bytes for demonstration
                ret = ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                if (ret == -1) {
                    perror("ptrace SETREGS");
                    exit(EXIT_FAILURE);
                }
                printf("Parent: Modified RIP to = %llx\n", regs.rip);

                // Read a word from child's memory
                addr = regs.rsp; // Let's use the stack pointer as an example address
                ret = ptrace(PTRACE_PEEKDATA, child_pid, (void *)addr, NULL);
                if (ret == -1 && errno != 0) {
                    perror("ptrace PEEKDATA");
                    exit(EXIT_FAILURE);
                }
                printf("Parent: Read word from child's stack (address %lx) = %lx\n", addr, ret);

                // Write a new word to child's memory
                data = 0x12345678; // Example data
                ret = ptrace(PTRACE_POKEDATA, child_pid, (void *)addr, (void *)data);
                if (ret == -1) {
                    perror("ptrace POKEDATA");
                    exit(EXIT_FAILURE);
                }
                printf("Parent: Wrote word to child's stack (address %lx) = %lx\n", addr, data);

                // Continue the child process
                if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) == -1) {
                    perror("ptrace CONT");
                    exit(EXIT_FAILURE);
                }

                // Wait for the child to finish
                waitpid(child_pid, &status, 0);
                if (WIFEXITED(status)) {
                    printf("Parent: Child exited with status %d.\n", WEXITSTATUS(status));
                }
            }
        }
    }

    return 0;
}

// gcc -o ptrace_basic_test ptrace_basic_test.c
// sudo ./ptrace_basic_test