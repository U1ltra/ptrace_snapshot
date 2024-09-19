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
#define DATA_V1 0x12345678  // Arbitrary data for snapshot v1
#define DATA_V2 0xa9876543  // Arbitrary data for snapshot v2
#define BAD_VALUE 0xBADBADBADBAD  // Arbitrary bad data

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
    unsigned char *user_buffer = malloc(SNAPSHOT_SIZE);  // Buffer for PTRACE_GETSNAPSHOT data

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

        // Initialize the memory with some test data (v1)
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

            // Read the address of the target memory region from user input
            printf("Enter the target address of the memory region to snapshot: ");
            scanf("%lx", &target_addr);

            // Write new data (v1) to the memory region
            unsigned long new_data = DATA_V1;
            for (int i = 0; i < SNAPSHOT_SIZE / sizeof(unsigned long); i++) {
                ret = ptrace(PTRACE_POKEDATA, child_pid, target_addr + i * sizeof(unsigned long), new_data);
                if (ret == -1) {
                    perror("ptrace POKEDATA v1");
                    exit(EXIT_FAILURE);
                }
            }
            printf("Parent: Wrote new data (v1) to memory region.\n");

            printf("Parent: Taking snapshot...\n");

            // Perform PTRACE_SNAPSHOT (v1)
            ret = ptrace(PTRACE_SNAPSHOT, child_pid, target_addr, SNAPSHOT_SIZE);
            if (ret == -1) {
                perror("ptrace SNAPSHOT v1");
                exit(EXIT_FAILURE);
            }
            printf("Parent: Snapshot (v1) taken successfully.\n");

            // Write new data (v2) to the memory region
            new_data = DATA_V2;
            for (int i = 0; i < SNAPSHOT_SIZE / sizeof(unsigned long); i++) {
                ret = ptrace(PTRACE_POKEDATA, child_pid, target_addr + i * sizeof(unsigned long), new_data);
                if (ret == -1) {
                    perror("ptrace POKEDATA v2");
                    exit(EXIT_FAILURE);
                }
            }
            printf("Parent: Wrote new data (v2) to memory region.\n");

            // Perform another snapshot (v2)
            ret = ptrace(PTRACE_SNAPSHOT, child_pid, target_addr, SNAPSHOT_SIZE);
            if (ret == -1) {
                perror("ptrace SNAPSHOT v2");
                exit(EXIT_FAILURE);
            }
            printf("Parent: Snapshot (v2) taken successfully.\n");

            // Write bad data to the memory region
            unsigned long bad_data = BAD_VALUE;
            for (int i = 0; i < SNAPSHOT_SIZE / sizeof(unsigned long); i++) {
                ret = ptrace(PTRACE_POKEDATA, child_pid, target_addr + i * sizeof(unsigned long), bad_data);
                if (ret == -1) {
                    perror("ptrace POKEDATA bad");
                    exit(EXIT_FAILURE);
                }
            }
            printf("Parent: Wrote bad data to memory region.\n");

            // Perform PTRACE_GETSNAPSHOT to read the snapshot (v2)
            ret = ptrace(PTRACE_GETSNAPSHOT, child_pid, target_addr, (unsigned long)user_buffer);
            if (ret == -1) {
                perror("ptrace GETSNAPSHOT");
                exit(EXIT_FAILURE);
            }

            printf("Parent: Snapshot data read back (v2):\n");
            for (int i = 0; i < SNAPSHOT_SIZE; i++) {
                printf("%02x ", user_buffer[i]);
                if ((i + 1) % 16 == 0)
                    printf("\n");
            }

            // peek the bad data
            for (int i = 0; i < SNAPSHOT_SIZE / sizeof(unsigned long); i++) {
                ret = ptrace(PTRACE_PEEKDATA, child_pid, target_addr + i * sizeof(unsigned long), NULL);
                if (ret == -1) {
                    perror("ptrace PEEKDATA bad");
                    exit(EXIT_FAILURE);
                }
                // split the data into bytes
                for (int j = 0; j < sizeof(unsigned long); j++) {
                    user_buffer[i * sizeof(unsigned long) + j] = (ret >> (j * 8)) & 0xff;
                }
            }

            // print the restored data
            printf("Parent: Bad data:\n");
            for (int i = 0; i < SNAPSHOT_SIZE; i++) {
                printf("%02x ", user_buffer[i]);
                if ((i + 1) % 16 == 0)
                    printf("\n");
            }

            // Restore the snapshot (v2) to the memory region
            ret = ptrace(PTRACE_RESTORE, child_pid, target_addr, SNAPSHOT_SIZE);
            if (ret == -1) {
                perror("ptrace RESTORE");
                exit(EXIT_FAILURE);
            }
            printf("Parent: Restored snapshot (v2).\n");

            // peek the restored data
            for (int i = 0; i < SNAPSHOT_SIZE / sizeof(unsigned long); i++) {
                ret = ptrace(PTRACE_PEEKDATA, child_pid, target_addr + i * sizeof(unsigned long), NULL);
                if (ret == -1) {
                    perror("ptrace PEEKDATA restored");
                    exit(EXIT_FAILURE);
                }
                // split the data into bytes
                for (int j = 0; j < sizeof(unsigned long); j++) {
                    user_buffer[i * sizeof(unsigned long) + j] = (ret >> (j * 8)) & 0xff;
                }
            }

            // print the restored data
            printf("Parent: Restored data:\n");
            for (int i = 0; i < SNAPSHOT_SIZE; i++) {
                printf("%02x ", user_buffer[i]);
                if ((i + 1) % 16 == 0)
                    printf("\n");
            }


            // Detach from the child process
            if (ptrace(PTRACE_DETACH, child_pid, NULL, NULL) == -1) {
                perror("ptrace DETACH");
                exit(EXIT_FAILURE);
            }
            printf("Parent: Detached from child.\n");
        }
    }

    free(user_buffer);
    return 0;
}

// gcc -o ptrace_test ptrace_test.c
// sudo ./ptrace_test
