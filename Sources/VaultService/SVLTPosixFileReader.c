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

    // A selected path is revalidated as a regular file by Swift, but that
    // check and open are still a TOCTOU boundary. O_NONBLOCK prevents a
    // malicious or stale selection that resolves to a FIFO/device from
    // hanging the Agent's single Catalog actor indefinitely; regular files
    // retain the same read semantics.
    const int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
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

int svlt_create_file(const char *path, int *descriptor) {
    if (path == NULL || descriptor == NULL) {
        return EINVAL;
    }

    const int opened = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (opened < 0) {
        return errno;
    }
    *descriptor = opened;
    return 0;
}

int svlt_write_file_descriptor(int descriptor, const void *bytes, size_t length) {
    if (descriptor < 0 || (bytes == NULL && length != 0)) {
        return EINVAL;
    }

    const uint8_t *source = (const uint8_t *)bytes;
    size_t written = 0;
    while (written < length) {
        const ssize_t count = write(descriptor, source + written, length - written);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        if (count == 0) {
            return EIO;
        }
        written += (size_t)count;
    }
    return 0;
}

int svlt_fsync_file_descriptor(int descriptor) {
    if (descriptor < 0) {
        return EINVAL;
    }
    if (fsync(descriptor) != 0) {
        return errno;
    }
    return 0;
}

int svlt_close_file_descriptor(int descriptor) {
    if (descriptor < 0) {
        return EINVAL;
    }
    if (close(descriptor) != 0) {
        return errno;
    }
    return 0;
}

int svlt_replace_file(const char *temporaryPath, const char *targetPath) {
    if (temporaryPath == NULL || targetPath == NULL) {
        return EINVAL;
    }
    if (rename(temporaryPath, targetPath) != 0) {
        return errno;
    }
    return 0;
}

int svlt_fsync_directory(const char *parentPath) {
    if (parentPath == NULL) {
        return EINVAL;
    }
    // The selected Catalog may live on a provider-backed or otherwise
    // untrusted filesystem. Directory open is part of the commit durability
    // path, but it must not block the Agent's single IPC worker indefinitely.
    // A normal local directory keeps the same fsync semantics; a provider
    // that cannot service this non-blocking probe returns an errno instead.
    const int descriptor = open(parentPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
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

int svlt_rename_file(const char *sourcePath, const char *destinationPath) {
    if (sourcePath == NULL || destinationPath == NULL) {
        return EINVAL;
    }
    if (rename(sourcePath, destinationPath) != 0) {
        return errno;
    }
    return 0;
}

int svlt_unlink_file(const char *path) {
    if (path == NULL) {
        return EINVAL;
    }
    if (unlink(path) != 0) {
        return errno;
    }
    return 0;
}
