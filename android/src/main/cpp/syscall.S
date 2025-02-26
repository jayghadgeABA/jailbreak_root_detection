#include "syscall.h"

// Declare the error function as an external symbol for assembly
.extern __set_errno_internal

// For ARM 32-bit architecture (armeabi-v7a)
#if defined(__arm__)

#define SYSCALL_TRAP 0

.syntax unified

// my_openat implementation
ENTRY(my_openat)
    mov ip, r7
    ldr r7, =__NR_openat
    swi #SYSCALL_TRAP
    mov r7, ip
    cmn r0, #(MAX_ERRNO + 1)
    bxls lr
    neg r0, r0
    b __set_errno_internal
END(my_openat)

// my_read implementation
ENTRY(my_read)
    mov ip, r7
    ldr r7, =__NR_read
    swi #SYSCALL_TRAP
    mov r7, ip
    cmn r0, #(MAX_ERRNO + 1)
    bxls lr
    neg r0, r0
    b __set_errno_internal
END(my_read)

// my_ptrace implementation
ENTRY(my_ptrace)
    mov ip, r7
    ldr r7, =__NR_ptrace
    swi #SYSCALL_TRAP
    mov r7, ip
    cmn r0, #(MAX_ERRNO + 1)
    bxls lr
    neg r0, r0
    b __set_errno_internal
END(my_ptrace)

#endif

// For ARM64 (aarch64) architecture
#if defined(__aarch64__)

// my_openat implementation
ENTRY(my_openat)
    mov     x8, __NR_openat
    svc     #0
    cmn     x0, #(MAX_ERRNO + 1)
    b.lo    1f
    neg     x0, x0
    b       __set_errno_internal
1:
    ret
END(my_openat)

// my_read implementation  
ENTRY(my_read)
    mov     x8, __NR_read
    svc     #0
    cmn     x0, #(MAX_ERRNO + 1)
    b.lo    1f
    neg     x0, x0
    b       __set_errno_internal
1:
    ret
END(my_read)

// my_ptrace implementation
ENTRY(my_ptrace)
    mov     x8, __NR_ptrace
    svc     #0
    cmn     x0, #(MAX_ERRNO + 1)
    b.lo    1f
    neg     x0, x0
    b       __set_errno_internal
1:
    ret
END(my_ptrace)

#endif

// For x86_64 architecture
#if defined(__x86_64__)

// my_openat implementation
ENTRY(my_openat)
    mov     $__NR_openat, %eax
    syscall
    cmp     $-MAX_ERRNO, %rax
    jb      1f
    neg     %rax
    mov     %rax, %rdi
    call    __set_errno_internal
1:
    ret
END(my_openat)

// my_read implementation
ENTRY(my_read)
    mov     $__NR_read, %eax
    syscall
    cmp     $-MAX_ERRNO, %rax
    jb      1f
    neg     %rax
    mov     %rax, %rdi
    call    __set_errno_internal
1:
    ret
END(my_read)

// my_ptrace implementation
ENTRY(my_ptrace)
    mov     $__NR_ptrace, %eax
    syscall
    cmp     $-MAX_ERRNO, %rax
    jb      1f
    neg     %rax
    mov     %rax, %rdi
    call    __set_errno_internal
1:
    ret
END(my_ptrace)

#endif