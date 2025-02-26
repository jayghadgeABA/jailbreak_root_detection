// Declare the error function as an external symbol for assembly
.extern __set_errno_internal

#if defined(__arm__)
// ARM 32-bit architecture (armeabi-v7a)

.syntax unified
.text
.global my_openat
.type my_openat, %function
my_openat:
    mov ip, r7
    ldr r7, =322  // __NR_openat for ARM
    swi #0
    mov r7, ip
    cmn r0, #4096  // MAX_ERRNO
    bxls lr
    neg r0, r0
    b __set_errno_internal
.size my_openat, .-my_openat

.text
.global my_read
.type my_read, %function
my_read:
    mov ip, r7
    ldr r7, =3  // __NR_read for ARM
    swi #0
    mov r7, ip
    cmn r0, #4096
    bxls lr
    neg r0, r0
    b __set_errno_internal
.size my_read, .-my_read

.text
.global my_ptrace
.type my_ptrace, %function
my_ptrace:
    mov ip, r7
    ldr r7, =26  // __NR_ptrace for ARM
    swi #0
    mov r7, ip
    cmn r0, #4096
    bxls lr
    neg r0, r0
    b __set_errno_internal
.size my_ptrace, .-my_ptrace

#elif defined(__aarch64__)
// ARM64 architecture

.text
.global my_openat
.type my_openat, %function
my_openat:
    mov x8, #56  // __NR_openat for ARM64
    svc #0
    cmn x0, #4096
    b.lo 1f
    neg x0, x0
    b __set_errno_internal
1:
    ret
.size my_openat, .-my_openat

.text
.global my_read
.type my_read, %function
my_read:
    mov x8, #63  // __NR_read for ARM64
    svc #0
    cmn x0, #4096
    b.lo 1f
    neg x0, x0
    b __set_errno_internal
1:
    ret
.size my_read, .-my_read

.text
.global my_ptrace
.type my_ptrace, %function
my_ptrace:
    mov x8, #117  // __NR_ptrace for ARM64
    svc #0
    cmn x0, #4096
    b.lo 1f
    neg x0, x0
    b __set_errno_internal
1:
    ret
.size my_ptrace, .-my_ptrace

#elif defined(__i386__)
// x86 32-bit architecture - PIC-compatible version

.text
.global my_openat
.type my_openat, @function
my_openat:
    pushl %ebx                  // Save ebx (required for PIC)
    movl $295, %eax             // __NR_openat for x86
    movl 8(%esp), %ebx          // First arg (adjusted for pushed ebx)
    movl 12(%esp), %ecx         // Second arg
    movl 16(%esp), %edx         // Third arg
    movl 20(%esp), %esi         // Fourth arg
    int $0x80
    cmpl $-4096, %eax
    jae 1f
    popl %ebx                   // Restore ebx
    ret
1:  // Error path
    negl %eax
    pushl %eax
    call __set_errno_internal@PLT  // Use PLT for PIC
    addl $4, %esp
    movl $-1, %eax
    popl %ebx                   // Restore ebx
    ret
.size my_openat, .-my_openat

.text
.global my_read
.type my_read, @function
my_read:
    pushl %ebx                  // Save ebx
    movl $3, %eax               // __NR_read for x86
    movl 8(%esp), %ebx          // First arg
    movl 12(%esp), %ecx         // Second arg
    movl 16(%esp), %edx         // Third arg
    int $0x80
    cmpl $-4096, %eax
    jae 1f
    popl %ebx                   // Restore ebx
    ret
1:  // Error path
    negl %eax
    pushl %eax
    call __set_errno_internal@PLT  // Use PLT for PIC
    addl $4, %esp
    movl $-1, %eax
    popl %ebx                   // Restore ebx
    ret
.size my_read, .-my_read

.text
.global my_ptrace
.type my_ptrace, @function
my_ptrace:
    pushl %ebx                  // Save ebx
    movl $26, %eax              // __NR_ptrace for x86
    movl 8(%esp), %ebx          // First arg
    movl 12(%esp), %ecx         // Second arg
    movl 16(%esp), %edx         // Third arg
    movl 20(%esp), %esi         // Fourth arg
    int $0x80
    cmpl $-4096, %eax
    jae 1f
    popl %ebx                   // Restore ebx
    ret
1:  // Error path
    negl %eax
    pushl %eax
    call __set_errno_internal@PLT  // Use PLT for PIC
    addl $4, %esp
    movl $-1, %eax
    popl %ebx                   // Restore ebx
    ret
.size my_ptrace, .-my_ptrace

#elif defined(__x86_64__)
// x86_64 architecture

.text
.global my_openat
.type my_openat, @function
my_openat:
    mov $257, %eax  // __NR_openat for x86_64
    syscall
    cmp $-4096, %rax
    jb 1f
    neg %rax
    mov %rax, %rdi
    call __set_errno_internal@PLT  // Use PLT for PIC
1:
    ret
.size my_openat, .-my_openat

.text
.global my_read
.type my_read, @function
my_read:
    mov $0, %eax  // __NR_read for x86_64
    syscall
    cmp $-4096, %rax
    jb 1f
    neg %rax
    mov %rax, %rdi
    call __set_errno_internal@PLT  // Use PLT for PIC
1:
    ret
.size my_read, .-my_read

.text
.global my_ptrace
.type my_ptrace, @function
my_ptrace:
    mov $101, %eax  // __NR_ptrace for x86_64
    syscall
    cmp $-4096, %rax
    jb 1f
    neg %rax
    mov %rax, %rdi
    call __set_errno_internal@PLT  // Use PLT for PIC
1:
    ret
.size my_ptrace, .-my_ptrace

#endif