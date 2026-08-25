#ifndef SVLT_POSIX_FILE_READER_H
#define SVLT_POSIX_FILE_READER_H

#include <stddef.h>

/// Reads one regular file without Foundation/Swift Darwin overlay calls.
/// Returns 0 on success or an errno-style failure code. The returned buffer
/// is owned by the caller and must be released with svlt_free_file.
int svlt_read_file(const char *path, void **bytes, size_t *length);

void svlt_free_file(void *bytes);

int svlt_write_file(const char *path, const void *bytes, size_t length);
int svlt_replace_file(const char *temporaryPath, const char *targetPath, const char *parentPath);

#endif
