/*
  Copyright (c) 2009-2017 Dave Gamble and cJSON contributors
  Simplified implementation for basic DLL
*/

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <float.h>

#define CJSON_HIDE_SYMBOLS
#include "cJSON.h"

/* define our own boolean type */
#define true ((cJSON_bool)1)
#define false ((cJSON_bool)0)

static const char *cJSON_Version_str = "1.7.15";

CJSON_PUBLIC(const char*) cJSON_Version(void)
{
    return cJSON_Version_str;
}

static void *cJSON_malloc_fn(size_t sz) { return malloc(sz); }
static void  cJSON_free_fn(void *ptr)   { free(ptr); }

static cJSON_Hooks global_hooks = { cJSON_malloc_fn, cJSON_free_fn };

CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)
{
    if (!hooks) {
        global_hooks.malloc_fn = cJSON_malloc_fn;
        global_hooks.free_fn   = cJSON_free_fn;
        return;
    }
    global_hooks.malloc_fn = hooks->malloc_fn ? hooks->malloc_fn : cJSON_malloc_fn;
    global_hooks.free_fn   = hooks->free_fn   ? hooks->free_fn   : cJSON_free_fn;
}

static cJSON *cJSON_New_Item(void)
{
    cJSON *node = (cJSON*)global_hooks.malloc_fn(sizeof(cJSON));
    if (node) memset(node, 0, sizeof(cJSON));
    return node;
}

CJSON_PUBLIC(void) cJSON_Delete(cJSON *item)
{
    cJSON *next = NULL;
    while (item != NULL)
    {
        next = item->next;
        if (!(item->type & cJSON_IsReference) && (item->child != NULL))
            cJSON_Delete(item->child);
        if (!(item->type & cJSON_IsReference) && (item->valuestring != NULL))
            global_hooks.free_fn(item->valuestring);
        if (!(item->type & cJSON_StringIsConst) && (item->string != NULL))
            global_hooks.free_fn(item->string);
        global_hooks.free_fn(item);
        item = next;
    }
}

/* ---- Parser ---- */
static const char *error_ptr = NULL;

CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void) { return error_ptr; }

static unsigned char *ensure(char **p, size_t *len, size_t needed)
{
    char *newbuf;
    size_t newsize;
    if (*p == NULL) {
        newsize = needed + 64;
        *p = (char*)global_hooks.malloc_fn(newsize);
        if (!*p) return NULL;
        *len = newsize;
        return (unsigned char*)*p;
    }
    if (*len >= needed) return (unsigned char*)*p;
    newsize = needed + 64;
    newbuf = (char*)global_hooks.malloc_fn(newsize);
    if (!newbuf) return NULL;
    memcpy(newbuf, *p, *len);
    global_hooks.free_fn(*p);
    *p = newbuf;
    *len = newsize;
    return (unsigned char*)*p;
}

/* skip whitespace */
static const char *skip(const char *in)
{
    while (in && *in && (unsigned char)*in <= 32) in++;
    return in;
}

static char *cJSON_strdup(const char *str)
{
    size_t len;
    char *copy;
    if (!str) return NULL;
    len = strlen(str) + 1;
    copy = (char*)global_hooks.malloc_fn(len);
    if (!copy) return NULL;
    memcpy(copy, str, len);
    return copy;
}

/* parse a string */
static const char *parse_string(cJSON *item, const char *str)
{
    const char *ptr = str + 1;
    char *ptr2;
    char *out;
    int len = 0;
    unsigned uc, uc2;

    if (*str != '\"') { error_ptr = str; return NULL; }

    while (*ptr != '\"' && *ptr && ++len)
        if (*ptr++ == '\\') ptr++;

    out = (char*)global_hooks.malloc_fn(len + 1);
    if (!out) return NULL;

    ptr = str + 1;
    ptr2 = out;
    while (*ptr != '\"' && *ptr)
    {
        if (*ptr != '\\') *ptr2++ = *ptr++;
        else
        {
            ptr++;
            switch (*ptr)
            {
            case 'b': *ptr2++ = '\b'; break;
            case 'f': *ptr2++ = '\f'; break;
            case 'n': *ptr2++ = '\n'; break;
            case 'r': *ptr2++ = '\r'; break;
            case 't': *ptr2++ = '\t'; break;
            case 'u':
                sscanf(ptr + 1, "%4x", &uc);
                ptr += 4;
                if ((uc >= 0xDC00 && uc <= 0xDFFF) || uc == 0) break;
                if (uc >= 0xD800 && uc <= 0xDBFF)
                {
                    if (ptr[1] != '\\' || ptr[2] != 'u') break;
                    sscanf(ptr + 3, "%4x", &uc2);
                    ptr += 6;
                    uc = 0x10000 + (((uc & 0x3FF) << 10) | (uc2 & 0x3FF));
                }
                if (uc < 0x80)       *ptr2++ = (char)uc;
                else if (uc < 0x800) { *ptr2++ = (char)(0xC0 | (uc >> 6)); *ptr2++ = (char)(0x80 | (uc & 0x3F)); }
                else if (uc < 0x10000) { *ptr2++ = (char)(0xE0 | (uc >> 12)); *ptr2++ = (char)(0x80 | ((uc >> 6) & 0x3F)); *ptr2++ = (char)(0x80 | (uc & 0x3F)); }
                else { *ptr2++ = (char)(0xF0 | (uc >> 18)); *ptr2++ = (char)(0x80 | ((uc >> 12) & 0x3F)); *ptr2++ = (char)(0x80 | ((uc >> 6) & 0x3F)); *ptr2++ = (char)(0x80 | (uc & 0x3F)); }
                break;
            default: *ptr2++ = *ptr; break;
            }
            ptr++;
        }
    }
    *ptr2 = 0;
    if (*ptr == '\"') ptr++;
    item->valuestring = out;
    item->type = cJSON_String;
    return ptr;
}

/* parse a number */
static const char *parse_number(cJSON *item, const char *num)
{
    double n = 0, sign = 1, scale = 0;
    int subscale = 0, signsubscale = 1;
    if (*num == '-') { sign = -1; num++; }
    if (*num == '0') num++;
    else if (*num >= '1' && *num <= '9') { do { n = n * 10.0 + (*num++ - '0'); } while (*num >= '0' && *num <= '9'); }
    if (*num == '.' && num[1] >= '0' && num[1] <= '9') { num++; do { n = n * 10.0 + (*num++ - '0'); scale--; } while (*num >= '0' && *num <= '9'); }
    if (*num == 'e' || *num == 'E') {
        num++;
        if (*num == '+') num++;
        else if (*num == '-') { signsubscale = -1; num++; }
        while (*num >= '0' && *num <= '9') subscale = subscale * 10 + (*num++ - '0');
    }
    n = sign * n * pow(10.0, (scale + subscale * signsubscale));
    item->valuedouble = n;
    item->valueint = (int)n;
    item->type = cJSON_Number;
    return num;
}

static const char *parse_value(cJSON *item, const char *value);
static const char *parse_array(cJSON *item, const char *value);
static const char *parse_object(cJSON *item, const char *value);

static const char *parse_value(cJSON *item, const char *value)
{
    if (!value) return NULL;
    value = skip(value);
    if (!strncmp(value, "null",  4)) { item->type = cJSON_NULL;  return value + 4; }
    if (!strncmp(value, "false", 5)) { item->type = cJSON_False; return value + 5; }
    if (!strncmp(value, "true",  4)) { item->type = cJSON_True;  return value + 4; }
    if (*value == '\"') return parse_string(item, value);
    if (*value == '-' || (*value >= '0' && *value <= '9')) return parse_number(item, value);
    if (*value == '[') return parse_array(item, value);
    if (*value == '{') return parse_object(item, value);
    error_ptr = value;
    return NULL;
}

static const char *parse_array(cJSON *item, const char *value)
{
    cJSON *child;
    item->type = cJSON_Array;
    value = skip(value + 1);
    if (*value == ']') return value + 1;
    item->child = child = cJSON_New_Item();
    if (!item->child) return NULL;
    value = skip(parse_value(child, skip(value)));
    if (!value) return NULL;
    while (*value == ',')
    {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        value = skip(parse_value(child, skip(value + 1)));
        if (!value) return NULL;
    }
    if (*value == ']') return value + 1;
    error_ptr = value;
    return NULL;
}

static const char *parse_object(cJSON *item, const char *value)
{
    cJSON *child;
    item->type = cJSON_Object;
    value = skip(value + 1);
    if (*value == '}') return value + 1;
    item->child = child = cJSON_New_Item();
    if (!item->child) return NULL;
    value = skip(parse_string(child, skip(value)));
    if (!value) return NULL;
    child->string = child->valuestring;
    child->valuestring = NULL;
    if (*value != ':') { error_ptr = value; return NULL; }
    value = skip(parse_value(child, skip(value + 1)));
    if (!value) return NULL;
    while (*value == ',')
    {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        value = skip(parse_string(child, skip(value + 1)));
        if (!value) return NULL;
        child->string = child->valuestring;
        child->valuestring = NULL;
        if (*value != ':') { error_ptr = value; return NULL; }
        value = skip(parse_value(child, skip(value + 1)));
        if (!value) return NULL;
    }
    if (*value == '}') return value + 1;
    error_ptr = value;
    return NULL;
}

CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value)
{
    return cJSON_ParseWithOpts(value, NULL, false);
}

CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)
{
    return cJSON_ParseWithLengthOpts(value, buffer_length, NULL, false);
}

CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON_bool require_null_terminated)
{
    cJSON *c = cJSON_New_Item();
    const char *end = NULL;
    error_ptr = NULL;
    if (!c) return NULL;
    end = parse_value(c, skip(value));
    if (!end) { cJSON_Delete(c); return NULL; }
    if (require_null_terminated) {
        end = skip(end);
        if (*end) { cJSON_Delete(c); error_ptr = end; return NULL; }
    }
    if (return_parse_end) *return_parse_end = end;
    return c;
}

CJSON_PUBLIC(cJSON *) cJSON_ParseWithLengthOpts(const char *value, size_t buffer_length, const char **return_parse_end, cJSON_bool require_null_terminated)
{
    (void)buffer_length;
    return cJSON_ParseWithOpts(value, return_parse_end, require_null_terminated);
}

/* ---- Printer ---- */
typedef struct {
    char *buffer;
    size_t length;
    size_t offset;
    int noalloc;
    cJSON_bool fmt;
} printbuffer;

static cJSON_bool ensure_buf(printbuffer *p, size_t needed)
{
    char *newbuf;
    size_t newsize;
    if (p->noalloc) return false;
    if (p->offset + needed <= p->length) return true;
    newsize = p->offset + needed + 256;
    newbuf = (char*)global_hooks.malloc_fn(newsize);
    if (!newbuf) return false;
    if (p->buffer) { memcpy(newbuf, p->buffer, p->offset); global_hooks.free_fn(p->buffer); }
    p->buffer = newbuf;
    p->length = newsize;
    return true;
}

static void print_string_ptr(const char *str, printbuffer *p)
{
    const char *ptr;
    char *ptr2;
    size_t len = 0;
    unsigned char token;
    if (!str) { if (ensure_buf(p, 3)) { p->buffer[p->offset++] = '\"'; p->buffer[p->offset++] = '\"'; p->buffer[p->offset] = 0; } return; }
    for (ptr = str; *ptr; ptr++) { len++; if ((unsigned char)*ptr < 32 || *ptr == '\"' || *ptr == '\\') len++; }
    if (!ensure_buf(p, len + 3)) return;
    ptr2 = p->buffer + p->offset;
    *ptr2++ = '\"';
    for (ptr = str; *ptr; ptr++) {
        if ((unsigned char)*ptr > 31 && *ptr != '\"' && *ptr != '\\') *ptr2++ = *ptr;
        else {
            *ptr2++ = '\\';
            switch (token = *ptr) {
            case '\\': *ptr2++ = '\\'; break;
            case '\"': *ptr2++ = '\"'; break;
            case '\b': *ptr2++ = 'b'; break;
            case '\f': *ptr2++ = 'f'; break;
            case '\n': *ptr2++ = 'n'; break;
            case '\r': *ptr2++ = 'r'; break;
            case '\t': *ptr2++ = 't'; break;
            default: ptr2 += sprintf(ptr2, "u%04x", token); break;
            }
        }
    }
    *ptr2++ = '\"';
    *ptr2 = 0;
    p->offset = (size_t)(ptr2 - p->buffer);
}

static void print_value(cJSON *item, int depth, cJSON_bool fmt, printbuffer *p);

static void print_number(cJSON *item, printbuffer *p)
{
    char str[64];
    double d = item->valuedouble;
    if (d == 0) { if (ensure_buf(p, 2)) { p->buffer[p->offset++] = '0'; p->buffer[p->offset] = 0; } }
    else if (fabs(((double)item->valueint) - d) <= DBL_EPSILON && d <= INT_MAX && d >= INT_MIN) {
        if (ensure_buf(p, 21)) { sprintf(str, "%d", item->valueint); memcpy(p->buffer + p->offset, str, strlen(str)); p->offset += strlen(str); p->buffer[p->offset] = 0; }
    }
    else {
        if (ensure_buf(p, 64)) { sprintf(str, "%g", d); memcpy(p->buffer + p->offset, str, strlen(str)); p->offset += strlen(str); p->buffer[p->offset] = 0; }
    }
}

static void print_array(cJSON *item, int depth, cJSON_bool fmt, printbuffer *p)
{
    cJSON *child = item->child;
    if (ensure_buf(p, 1)) { p->buffer[p->offset++] = '['; p->buffer[p->offset] = 0; }
    while (child) {
        print_value(child, depth + 1, fmt, p);
        if (child->next) { if (ensure_buf(p, 2)) { p->buffer[p->offset++] = ','; if (fmt) p->buffer[p->offset++] = ' '; p->buffer[p->offset] = 0; } }
        child = child->next;
    }
    if (ensure_buf(p, 1)) { p->buffer[p->offset++] = ']'; p->buffer[p->offset] = 0; }
}

static void print_object(cJSON *item, int depth, cJSON_bool fmt, printbuffer *p)
{
    cJSON *child = item->child;
    int i;
    if (ensure_buf(p, 2)) { p->buffer[p->offset++] = '{'; if (fmt) p->buffer[p->offset++] = '\n'; p->buffer[p->offset] = 0; }
    while (child) {
        if (fmt) { if (ensure_buf(p, depth + 2)) { for (i = 0; i < depth + 1; i++) p->buffer[p->offset++] = '\t'; p->buffer[p->offset] = 0; } }
        print_string_ptr(child->string, p);
        if (ensure_buf(p, 2)) { p->buffer[p->offset++] = ':'; if (fmt) p->buffer[p->offset++] = ' '; p->buffer[p->offset] = 0; }
        print_value(child, depth + 1, fmt, p);
        if (child->next) { if (ensure_buf(p, 2)) { p->buffer[p->offset++] = ','; p->buffer[p->offset] = 0; } }
        if (fmt) { if (ensure_buf(p, 2)) { p->buffer[p->offset++] = '\n'; p->buffer[p->offset] = 0; } }
        child = child->next;
    }
    if (fmt) { if (ensure_buf(p, depth + 2)) { for (i = 0; i < depth; i++) p->buffer[p->offset++] = '\t'; p->buffer[p->offset] = 0; } }
    if (ensure_buf(p, 1)) { p->buffer[p->offset++] = '}'; p->buffer[p->offset] = 0; }
}

static void print_value(cJSON *item, int depth, cJSON_bool fmt, printbuffer *p)
{
    if (!item) return;
    switch (item->type & 0xFF) {
    case cJSON_NULL:   if (ensure_buf(p, 5)) { memcpy(p->buffer + p->offset, "null",  4); p->offset += 4; p->buffer[p->offset] = 0; } break;
    case cJSON_False:  if (ensure_buf(p, 6)) { memcpy(p->buffer + p->offset, "false", 5); p->offset += 5; p->buffer[p->offset] = 0; } break;
    case cJSON_True:   if (ensure_buf(p, 5)) { memcpy(p->buffer + p->offset, "true",  4); p->offset += 4; p->buffer[p->offset] = 0; } break;
    case cJSON_Number: print_number(item, p); break;
    case cJSON_Raw:    if (item->valuestring) { size_t l = strlen(item->valuestring); if (ensure_buf(p, l + 1)) { memcpy(p->buffer + p->offset, item->valuestring, l); p->offset += l; p->buffer[p->offset] = 0; } } break;
    case cJSON_String: print_string_ptr(item->valuestring, p); break;
    case cJSON_Array:  print_array(item, depth, fmt, p); break;
    case cJSON_Object: print_object(item, depth, fmt, p); break;
    }
}

CJSON_PUBLIC(char *) cJSON_Print(const cJSON *item)
{
    printbuffer p = {0};
    p.fmt = true;
    print_value((cJSON*)item, 0, true, &p);
    return p.buffer;
}

CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)
{
    printbuffer p = {0};
    p.fmt = false;
    print_value((cJSON*)item, 0, false, &p);
    return p.buffer;
}

CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)
{
    (void)prebuffer;
    return fmt ? cJSON_Print(item) : cJSON_PrintUnformatted(item);
}

CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, const cJSON_bool format)
{
    printbuffer p = {0};
    p.buffer = buffer;
    p.length = (size_t)length;
    p.noalloc = 1;
    p.fmt = format;
    print_value(item, 0, format, &p);
    return true;
}

/* ---- Query ---- */
CJSON_PUBLIC(int) cJSON_GetArraySize(const cJSON *array)
{
    cJSON *c = array ? array->child : NULL;
    int i = 0;
    while (c) { i++; c = c->next; }
    return i;
}

CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int item)
{
    cJSON *c = array ? array->child : NULL;
    while (c && item > 0) { item--; c = c->next; }
    return c;
}

CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)
{
    cJSON *c = object ? object->child : NULL;
    while (c && strcmp(c->string, string)) c = c->next;
    return c;
}

CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string)
{
    return cJSON_GetObjectItem(object, string);
}

CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)
{
    return cJSON_GetObjectItem(object, string) ? true : false;
}

CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)
{
    if (!cJSON_IsString(item)) return NULL;
    return item->valuestring;
}

CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)
{
    if (!cJSON_IsNumber(item)) return (double)NAN;
    return item->valuedouble;
}

/* ---- Type checks ---- */
CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item) { return item ? (item->type & 0xFF) == cJSON_Invalid : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)   { return item ? (item->type & 0xFF) == cJSON_False   : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)    { return item ? (item->type & 0xFF) == cJSON_True    : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)    { return item ? ((item->type & 0xFF) == cJSON_True || (item->type & 0xFF) == cJSON_False) : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)    { return item ? (item->type & 0xFF) == cJSON_NULL    : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)  { return item ? (item->type & 0xFF) == cJSON_Number  : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)  { return item ? (item->type & 0xFF) == cJSON_String  : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)   { return item ? (item->type & 0xFF) == cJSON_Array   : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)  { return item ? (item->type & 0xFF) == cJSON_Object  : false; }
CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)     { return item ? (item->type & 0xFF) == cJSON_Raw     : false; }

/* ---- Create ---- */
CJSON_PUBLIC(cJSON *) cJSON_CreateNull(void)   { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_NULL;  return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)   { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_True;  return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)  { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_False; return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool b) { cJSON *i = cJSON_New_Item(); if (i) i->type = b ? cJSON_True : cJSON_False; return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num) { cJSON *i = cJSON_New_Item(); if (i) { i->type = cJSON_Number; i->valuedouble = num; i->valueint = (int)num; } return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string) { cJSON *i = cJSON_New_Item(); if (i) { i->type = cJSON_String; i->valuestring = cJSON_strdup(string); if (!i->valuestring) { cJSON_Delete(i); return NULL; } } return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw) { cJSON *i = cJSON_New_Item(); if (i) { i->type = cJSON_Raw; i->valuestring = cJSON_strdup(raw); if (!i->valuestring) { cJSON_Delete(i); return NULL; } } return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)  { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_Array;  return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void) { cJSON *i = cJSON_New_Item(); if (i) i->type = cJSON_Object; return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string) { cJSON *i = cJSON_New_Item(); if (i) { i->type = cJSON_String | cJSON_IsReference; i->valuestring = (char*)string; } return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child) { cJSON *i = cJSON_New_Item(); if (i) { i->type = cJSON_Object | cJSON_IsReference; i->child = (cJSON*)child; } return i; }
CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)  { cJSON *i = cJSON_New_Item(); if (i) { i->type = cJSON_Array  | cJSON_IsReference; i->child = (cJSON*)child; } return i; }

CJSON_PUBLIC(cJSON *) cJSON_CreateIntArray(const int *numbers, int count)
{
    int i; cJSON *n = NULL, *p = NULL, *a = cJSON_CreateArray();
    for (i = 0; a && i < count; i++) {
        n = cJSON_CreateNumber(numbers[i]);
        if (!n) { cJSON_Delete(a); return NULL; }
        if (!i) a->child = n; else { p->next = n; n->prev = p; }
        p = n;
    }
    return a;
}

CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)
{
    int i; cJSON *n = NULL, *p = NULL, *a = cJSON_CreateArray();
    for (i = 0; a && i < count; i++) {
        n = cJSON_CreateNumber((double)numbers[i]);
        if (!n) { cJSON_Delete(a); return NULL; }
        if (!i) a->child = n; else { p->next = n; n->prev = p; }
        p = n;
    }
    return a;
}

CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)
{
    int i; cJSON *n = NULL, *p = NULL, *a = cJSON_CreateArray();
    for (i = 0; a && i < count; i++) {
        n = cJSON_CreateNumber(numbers[i]);
        if (!n) { cJSON_Delete(a); return NULL; }
        if (!i) a->child = n; else { p->next = n; n->prev = p; }
        p = n;
    }
    return a;
}

CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char **strings, int count)
{
    int i; cJSON *n = NULL, *p = NULL, *a = cJSON_CreateArray();
    for (i = 0; a && i < count; i++) {
        n = cJSON_CreateString(strings[i]);
        if (!n) { cJSON_Delete(a); return NULL; }
        if (!i) a->child = n; else { p->next = n; n->prev = p; }
        p = n;
    }
    return a;
}

/* ---- Add ---- */
CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
    cJSON *c;
    if (!array || !item) return false;
    c = array->child;
    if (!c) { array->child = item; item->prev = item; item->next = NULL; }
    else {
        while (c->next) c = c->next;
        c->next = item; item->prev = c; item->next = NULL;
    }
    return true;
}

CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)
{
    if (!item) return false;
    if (item->string) global_hooks.free_fn(item->string);
    item->string = cJSON_strdup(string);
    return cJSON_AddItemToArray(object, item);
}

CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObjectCS(cJSON *object, const char *string, cJSON *item)
{
    if (!item) return false;
    item->string = (char*)string;
    item->type |= cJSON_StringIsConst;
    return cJSON_AddItemToArray(object, item);
}

CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)
{
    cJSON *ref = cJSON_New_Item();
    if (!ref) return false;
    memcpy(ref, item, sizeof(cJSON));
    ref->string = NULL;
    ref->type |= cJSON_IsReference;
    ref->next = ref->prev = NULL;
    return cJSON_AddItemToArray(array, ref);
}

CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON *item)
{
    cJSON *ref = cJSON_New_Item();
    if (!ref) return false;
    memcpy(ref, item, sizeof(cJSON));
    ref->string = cJSON_strdup(string);
    ref->type |= cJSON_IsReference;
    ref->next = ref->prev = NULL;
    return cJSON_AddItemToArray(object, ref);
}

/* ---- Detach/Delete ---- */
CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)
{
    if (!parent || !item) return NULL;
    if (item->prev) item->prev->next = item->next;
    if (item->next) item->next->prev = item->prev;
    if (item == parent->child) parent->child = item->next;
    item->prev = item->next = NULL;
    return item;
}

CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)
{
    return cJSON_DetachItemViaPointer(array, cJSON_GetArrayItem(array, which));
}

CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)
{
    cJSON_Delete(cJSON_DetachItemFromArray(array, which));
}

CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)
{
    return cJSON_DetachItemViaPointer(object, cJSON_GetObjectItem(object, string));
}

CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)
{
    return cJSON_DetachItemFromObject(object, string);
}

CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)
{
    cJSON_Delete(cJSON_DetachItemFromObject(object, string));
}

CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)
{
    cJSON_DeleteItemFromObject(object, string);
}

/* ---- Insert/Replace ---- */
CJSON_PUBLIC(cJSON_bool) cJSON_InsertItemInArray(cJSON *array, int which, cJSON *newitem)
{
    cJSON *after = cJSON_GetArrayItem(array, which);
    if (!after) return cJSON_AddItemToArray(array, newitem);
    newitem->next = after;
    newitem->prev = after->prev;
    if (after->prev) after->prev->next = newitem;
    else array->child = newitem;
    after->prev = newitem;
    return true;
}

CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJSON * replacement)
{
    if (!parent || !item || !replacement) return false;
    replacement->next = item->next;
    replacement->prev = item->prev;
    if (replacement->next) replacement->next->prev = replacement;
    if (replacement->prev) replacement->prev->next = replacement;
    if (parent->child == item) parent->child = replacement;
    item->next = item->prev = NULL;
    cJSON_Delete(item);
    return true;
}

CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)
{
    return cJSON_ReplaceItemViaPointer(array, cJSON_GetArrayItem(array, which), newitem);
}

CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newitem)
{
    cJSON *item = cJSON_GetObjectItem(object, string);
    if (!item) return false;
    if (newitem->string) global_hooks.free_fn(newitem->string);
    newitem->string = cJSON_strdup(string);
    return cJSON_ReplaceItemViaPointer(object, item, newitem);
}

CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string, cJSON *newitem)
{
    return cJSON_ReplaceItemInObject(object, string, newitem);
}

/* ---- Duplicate ---- */
CJSON_PUBLIC(cJSON *) cJSON_Duplicate(const cJSON *item, cJSON_bool recurse)
{
    cJSON *newitem, *cptr, *nptr = NULL, *newchild;
    if (!item) return NULL;
    newitem = cJSON_New_Item();
    if (!newitem) return NULL;
    newitem->type = item->type & (~cJSON_IsReference);
    newitem->valueint = item->valueint;
    newitem->valuedouble = item->valuedouble;
    if (item->valuestring) { newitem->valuestring = cJSON_strdup(item->valuestring); if (!newitem->valuestring) { cJSON_Delete(newitem); return NULL; } }
    if (item->string) { newitem->string = cJSON_strdup(item->string); if (!newitem->string) { cJSON_Delete(newitem); return NULL; } }
    if (!recurse) return newitem;
    cptr = item->child;
    while (cptr) {
        newchild = cJSON_Duplicate(cptr, true);
        if (!newchild) { cJSON_Delete(newitem); return NULL; }
        if (nptr) { nptr->next = newchild; newchild->prev = nptr; nptr = newchild; }
        else { newitem->child = newchild; nptr = newchild; }
        cptr = cptr->next;
    }
    return newitem;
}

/* ---- Compare ---- */
CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bool case_sensitive)
{
    (void)case_sensitive;
    if (!a || !b || (a->type & 0xFF) != (b->type & 0xFF)) return false;
    switch (a->type & 0xFF) {
    case cJSON_False: case cJSON_True: case cJSON_NULL: return true;
    case cJSON_Number: return (a->valuedouble == b->valuedouble);
    case cJSON_String: case cJSON_Raw: return (a->valuestring && b->valuestring && strcmp(a->valuestring, b->valuestring) == 0);
    default: return false;
    }
}

CJSON_PUBLIC(void) cJSON_Minify(char *json)
{
    char *into = json;
    if (!json) return;
    while (*json) {
        if (*json == ' ' || *json == '\t' || *json == '\r' || *json == '\n') json++;
        else if (*json == '/' && json[1] == '/') { while (*json && *json != '\n') json++; }
        else if (*json == '/' && json[1] == '*') { while (*json && !(*json == '*' && json[1] == '/')) json++; json += 2; }
        else if (*json == '\"') { *into++ = *json++; while (*json && *json != '\"') { if (*json == '\\') *into++ = *json++; *into++ = *json++; } *into++ = *json++; }
        else *into++ = *json++;
    }
    *into = 0;
}

/* ---- Convenience add ---- */
CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)
{
    cJSON *null = cJSON_CreateNull();
    if (cJSON_AddItemToObject(object, name, null)) return null;
    cJSON_Delete(null); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)
{
    cJSON *t = cJSON_CreateTrue();
    if (cJSON_AddItemToObject(object, name, t)) return t;
    cJSON_Delete(t); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)
{
    cJSON *f = cJSON_CreateFalse();
    if (cJSON_AddItemToObject(object, name, f)) return f;
    cJSON_Delete(f); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const cJSON_bool boolean)
{
    cJSON *b = cJSON_CreateBool(boolean);
    if (cJSON_AddItemToObject(object, name, b)) return b;
    cJSON_Delete(b); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number)
{
    cJSON *n = cJSON_CreateNumber(number);
    if (cJSON_AddItemToObject(object, name, n)) return n;
    cJSON_Delete(n); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string)
{
    cJSON *s = cJSON_CreateString(string);
    if (cJSON_AddItemToObject(object, name, s)) return s;
    cJSON_Delete(s); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const char * const raw)
{
    cJSON *r = cJSON_CreateRaw(raw);
    if (cJSON_AddItemToObject(object, name, r)) return r;
    cJSON_Delete(r); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)
{
    cJSON *o = cJSON_CreateObject();
    if (cJSON_AddItemToObject(object, name, o)) return o;
    cJSON_Delete(o); return NULL;
}
CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)
{
    cJSON *a = cJSON_CreateArray();
    if (cJSON_AddItemToObject(object, name, a)) return a;
    cJSON_Delete(a); return NULL;
}
