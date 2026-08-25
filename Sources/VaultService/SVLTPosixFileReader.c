#include "SVLTPosixFileReader.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

enum { SVLT_MAX_READ_BYTES = 64 * 1024 * 1024 };

int svlt_read_file(const char *path, void **bytes, size_t *length) {
    if (path == NULL || bytes == NULL || length == NULL) {
        return EINVAL;
    }

    *bytes = NULL;
    *length = 0;

    const int descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0) {
        return errno;
    }

    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0) {
        const int status = errno;
        close(descriptor);
        return status;
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_size < 0 || metadata.st_size > SVLT_MAX_READ_BYTES) {
        close(descriptor);
        return EINVAL;
    }

    size_t capacity = metadata.st_size > 0 ? (size_t)metadata.st_size : 1;
    uint8_t *buffer = malloc(capacity);
    if (buffer == NULL) {
        close(descriptor);
        return ENOMEM;
    }

    size_t used = 0;
    int status = 0;
    for (;;) {
        if (used == capacity) {
            if (capacity >= SVLT_MAX_READ_BYTES) {
                status = EFBIG;
                break;
            }
            size_t nextCapacity = capacity * 2;
            if (nextCapacity > SVLT_MAX_READ_BYTES) {
                nextCapacity = SVLT_MAX_READ_BYTES;
            }
            uint8_t *expanded = realloc(buffer, nextCapacity);
            if (expanded == NULL) {
                status = ENOMEM;
                break;
            }
            buffer = expanded;
            capacity = nextCapacity;
        }

        ssize_t count = read(descriptor, buffer + used, capacity - used);
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            status = errno;
            break;
        }
        used += (size_t)count;
    }

    close(descriptor);
    if (status != 0) {
        free(buffer);
        return status;
    }

    *bytes = buffer;
    *length = used;
    return 0;
}

void svlt_free_file(void *bytes) {
    free(bytes);
}

int svlt_write_file(const char *path, const void *bytes, size_t length) {
    if (path == NULL || (bytes == NULL && length != 0)) {
        return EINVAL;
    }

    const int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return errno;
    }

    const uint8_t *source = (const uint8_t *)bytes;
    size_t written = 0;
    int status = 0;
    while (written < length) {
        const ssize_t count = write(descriptor, source + written, length - written);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            status = errno;
            break;
        }
        if (count == 0) {
            status = EIO;
            break;
        }
        written += (size_t)count;
    }

    if (status == 0 && fsync(descriptor) != 0) {
        status = errno;
    }
    if (close(descriptor) != 0 && status == 0) {
        status = errno;
    }
    if (status != 0) {
        (void)unlink(path);
    }
    return status;
}

int svlt_replace_file(const char *temporaryPath, const char *targetPath, const char *parentPath) {
    if (temporaryPath == NULL || targetPath == NULL || parentPath == NULL) {
        return EINVAL;
    }
    if (rename(temporaryPath, targetPath) != 0) {
        return errno;
    }

    const int descriptor = open(parentPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (descriptor < 0) {
        return errno;
    }
    int status = 0;
    if (fsync(descriptor) != 0) {
        status = errno;
    }
    if (close(descriptor) != 0 && status == 0) {
        status = errno;
    }
    return status;
}
