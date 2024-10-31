#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct buffer {
    uint8_t *bytes;
    size_t num_bytes;
    size_t max_bytes;
} Buffer;

Buffer buf_new(void);
Buffer buf_new_with_capacity(size_t num_bytes);
void buf_free(Buffer buf);
void buf_grow_to(Buffer *buf, size_t num_bytes);
void buf_grow_by(Buffer *buf, size_t num_bytes);
size_t buf_append(Buffer *buf, const void *bytes, size_t len);
size_t buf_append_byte(Buffer *buf, uint8_t value);
size_t buf_append_half(Buffer *buf, uint16_t value);
size_t buf_append_word(Buffer *buf, uint32_t value);
size_t buf_append_long(Buffer *buf, uint64_t value);
size_t buf_append_addr(Buffer *buf, uintptr_t value);
size_t buf_append_str(Buffer *buf, const char *str);
size_t buf_append_hex(Buffer *buf, const char *str);

#ifdef BUFFER_IMPLEMENTATION
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Buffer buf_new(void)
{
    static Buffer result = { NULL, 0, 0 };
    return result;
}
Buffer buf_new_with_capacity(size_t num_bytes)
{
    Buffer result = buf_new();
    buf_grow_to(&result, num_bytes);
    return result;
}
void buf_free(Buffer buf)
{
    free(buf.bytes);
}
void buf_grow_to(Buffer *buf, size_t num_bytes)
{
    if (num_bytes <= buf->max_bytes) return;
    size_t max_bytes = 8;
    while (num_bytes > max_bytes) max_bytes *= 2;

    uint8_t *new_bytes = realloc(buf->bytes, max_bytes);
    if (!new_bytes) {
        fprintf(stderr, "Failed to allocate %zu bytes.\n", max_bytes);
        exit(EXIT_FAILURE);
    }
    buf->bytes = new_bytes;
    buf->max_bytes = max_bytes;
}
void buf_grow_by(Buffer *buf, size_t num_bytes)
{
    buf_grow_to(buf, buf->num_bytes + num_bytes);
}
size_t buf_append(Buffer *buf, const void *bytes, size_t len)
{
    buf_grow_by(buf, len);
    size_t off = buf->num_bytes;
    memcpy(&buf->bytes[buf->num_bytes], bytes, len);
    buf->num_bytes += len;
    return off;
}
size_t buf_append_byte(Buffer *buf, uint8_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_half(Buffer *buf, uint16_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_word(Buffer *buf, uint32_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_long(Buffer *buf, uint64_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_addr(Buffer *buf, uintptr_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_str(Buffer *buf, const char *str)
{
    return buf_append(buf, str, strlen(str) + 1);
}
size_t buf_append_hex(Buffer *buf, const char *str)
{
    size_t off = buf->num_bytes;
    while (*str) {
        int hi = *str++;
        int lo = *str++;
        char hexval[3] = { hi, lo, 0 };
        if (!isxdigit(hi)) lo = hi;
        if (!isxdigit(lo)) {
            if (isgraph(lo)) {
                fprintf(stderr, "'%c' is not a valid hex digit.\n", lo);
            } else {
                fprintf(stderr, "'\\x%02x' is not a valid hex digit.\n", lo);
            }
            exit(EXIT_FAILURE);
        }
        buf_append_byte(buf, strtoul(hexval, NULL, 16));
    }
    return off;
}
#endif