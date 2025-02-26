#include <jni.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>
#include <android/log.h> // This already defines ANDROID_LOG_INFO and ANDROID_LOG_ERROR
#include <sys/stat.h>
#include <cstdlib>
#include <string>
#include <elf.h>
#include <link.h>
#include <sys/ptrace.h>
#include <cinttypes> // For PRIx64 format specifier

#define unused_param(x) ((void)(x))

const char MAPS_FILE[] = "/proc/self/maps";
const char TAG[] = "JNI";

// customized syscalls
extern "C" int my_read(int, void *, size_t);
extern "C" int my_openat(int dirfd, const char *pathname, int flags, mode_t modes);
extern "C" long my_ptrace(int __request, ...);

// Our customized __set_errno_internal for syscall.S to use.
// we do not use the one from libc due to issue https://github.com/android/ndk/issues/1422
extern "C" long __set_errno_internal(int n) {
    errno = n;
    return -1;
}

/*  Read pseudo files in paths like /proc /sys
 *  *buf_ptr can be existing dynamic memory or nullptr (if so, this function
 *  will alloc memory automatically).
 *  remember to free the *buf_ptr because in no cases will *buf_ptr be
 *  freed inside this function
 *  return -1 on error, or non-negative value on success
 * */
int read_pseudo_file_at(const char *path, char **buf_ptr, size_t *buf_size_ptr,
                        bool use_customized_syscalls) {
    if (!path || !*path || !buf_ptr || !buf_size_ptr) {
        errno = EINVAL;
        return -1;
    }

    char *buf;
    size_t buf_size, total_read_size = 0;

    /* Existing dynamic buffer, or a new buffer? */
    buf_size = *buf_size_ptr;
    if (!buf_size)
        *buf_ptr = nullptr;
    buf = *buf_ptr;

    /* Open pseudo file */
    int fd = use_customized_syscalls ?
             my_openat(AT_FDCWD, MAPS_FILE, O_RDONLY | O_CLOEXEC, 0)
                                     : openat(AT_FDCWD, MAPS_FILE, O_RDONLY | O_CLOEXEC, 0);

    if (fd == -1) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "openat error %s : %d", strerror(errno), errno);
        return -1;
    }

    while (true) {
        if (total_read_size >= buf_size) {
            /* linear size growth
             * buf_size grow ~4k bytes each time, 32 bytes for zero padding
             * */
            buf_size = (total_read_size | 4095) + 4097 - 32;
            buf = (char *) realloc(buf, buf_size);
            if (!buf) {
                close(fd);
                errno = ENOMEM;
                return -1;
            }
            *buf_ptr = buf;
            *buf_size_ptr = buf_size;
        }

        size_t n = use_customized_syscalls ?
                   my_read(fd, buf + total_read_size, buf_size - total_read_size)
                                           : read(fd, buf + total_read_size,
                                                  buf_size - total_read_size);
        if (n > 0) {
            total_read_size += n;
        } else if (n == 0) {
            break;
        } else if (n == -1) {
            const int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }

    if (close(fd) == -1) {
        /* errno set by close(). */
        return -1;
    }

    if (total_read_size + 32 > buf_size)
        memset(buf + total_read_size, 0, 32);
    else
        memset(buf + total_read_size, 0, buf_size - total_read_size);

    errno = 0;
    return (int) total_read_size;
}

int read_line(int fd, char *ptr, unsigned int maxlen, jboolean use_customized_syscall) {
    int n;
    long rc;
    char c;

    for (n = 1; n < maxlen; n++) {
        rc = use_customized_syscall ? my_read(fd, &c, 1) : read(fd, &c, 1);
        if (rc == 1) {
            *ptr++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            if (n == 1)
                return 0;    /* EOF no data read */
            else
                break;       /* EOF, some data read */
        } else
            return (-1);     /* error */
    }
    *ptr = 0;
    return (n);
}

int wrap_endsWith(const char *str, const char *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenA = strlen(str);
    size_t lenB = strlen(suffix);
    if (lenB > lenA)
        return 0;
    return strncmp(str + lenA - lenB, suffix, lenB) == 0;
}

int elf_check_header(uintptr_t base_addr) {
    auto *ehdr = (ElfW(Ehdr) *) base_addr;
    if (0 != memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) return 0;
#if defined(__LP64__)
    if (ELFCLASS64 != ehdr->e_ident[EI_CLASS]) return 0;
#else
    if (ELFCLASS32 != ehdr->e_ident[EI_CLASS]) return 0;
#endif
    if (ELFDATA2LSB != ehdr->e_ident[EI_DATA]) return 0;
    if (EV_CURRENT != ehdr->e_ident[EI_VERSION]) return 0;
    if (ET_EXEC != ehdr->e_type && ET_DYN != ehdr->e_type) return 0;
    if (EV_CURRENT != ehdr->e_version) return 0;
    return 1;
}

int find_mem_string(uint64_