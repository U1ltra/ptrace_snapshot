#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define SNAPSHOT_SIZE 64  // Size of the memory region to snapshot

void read_memory_map(pid_t pid) {
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    
    FILE *maps_file = fopen(filename, "r");
    if (!maps_file) {
        perror("fopen");
        return;
    }
    
    printf("Memory map of child process %d:\n", pid);
    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        printf("%s", line);  // Print the memory map line by line
    }
    fclose(maps_file);
}

int main() {
    pid_t child_pid;
    long ret;
    int status;
    unsigned long target_addr;
    struct user_regs_struct regs;
    unsigned long data;

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

        // Allocate some memory for testing (on the heap)
        unsigned char *test_memory = malloc(SNAPSHOT_SIZE);
        if (!test_memory) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        // Initialize the memory with some test data
        for (int i = 0; i < SNAPSHOT_SIZE; i++) {
            test_memory[i] = (unsigned char)(i + 1);
        }

        // Print address of test_memory
        printf("Child: Address of test memory = %p\n", test_memory);

        // Keep the process running so the parent can interact with it
        while (1) {
            sleep(1);  // Loop indefinitely
        }

        // Free the memory (unreachable, example purpose only)
        free(test_memory);
        exit(EXIT_SUCCESS);
    } else {
        // Parent process (tracer)
        waitpid(child_pid, &status, 0); // Wait for child to stop

        if (WIFSTOPPED(status)) {
            printf("Parent: Child stopped, now attaching...\n");

            // Read the memory map of the child process
            read_memory_map(child_pid);

            // poke the child process
            printf("Parent: Enter the target address of the memory region to poke: ");
            scanf("%lx", &target_addr);
            data = 0x12345678; // Example data
            ret = ptrace(PTRACE_POKEDATA, child_pid, (void *)target_addr, (void *)data);
            if (ret == -1) {
                perror("ptrace POKEDATA");
                exit(EXIT_FAILURE);
            }
            printf("Parent: Wrote word to child's stack (address %lx) = %lx\n", target_addr, data);

            // Read the address of the target memory region from user input
            printf("Enter the target address of the memory region to snapshot: ");
            scanf("%lx", &target_addr);

            printf("Parent: Child stopped after attach. Taking snapshot...\n");

            // Perform PTRACE_SNAPSHOT
            ret = ptrace(PTRACE_SNAPSHOT, child_pid, target_addr, SNAPSHOT_SIZE);
            if (ret == -1) {
                perror("ptrace SNAPSHOT");
                exit(EXIT_FAILURE);
            }

            printf("Parent: Snapshot 1 taken successfully.\n");

            // Detach from the child process
            if (ptrace(PTRACE_DETACH, child_pid, NULL, NULL) == -1) {
                perror("ptrace DETACH");
                exit(EXIT_FAILURE);
            }
            printf("Parent: Detached from child.\n");
        }
    }

    return 0;
}

// gcc -o ptrace_snapshot_test ptrace_snapshot_test.c
// ./ptrace_snapshot_test
