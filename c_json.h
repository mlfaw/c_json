
#pragma once

#ifndef C_JSON_H
#define C_JSON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h> // malloc(), free()
#include <string.h> // memcpy()
#include <stdbool.h> // bool
#include <stdint.h>

#define C_JSON_FLAG_DUP_STRINGS (0x00000001)
#define C_JSON_FLAG_MALLOC      (0x00000002)
#define C_JSON_FLAG_
#define C_JSON_FLAG_FALSE       (0x00000004)
#define C_JSON_FLAG_TRUE        (0x00000008)
#define C_JSON_FLAG_BOOLEAN     (C_JSON_FLAG_FALSE | C_JSON_FLAG_TRUE)
#define C_JSON_FLAG_NULL        (0x00000010)
#define C_JSON_FLAG_STRING      (0x00000020)
#define C_JSON_FLAG_ARRAY       (0x00000040)
#define C_JSON_FLAG_OBJECT      (0x00000080)
#define C_JSON_FLAG_NUM_INVALID (0x00000100)
#define C_JSON_FLAG_NUM_DOUBLE  (0x00000200)
#define C_JSON_FLAG_NUM_INT64   (0x00000400)
#define C_JSON_FLAG_NUMBER      (C_JSON_FLAG_NUM_INVALID | C_JSON_FLAG_NUM_DOUBLE | C_JSON_FLAG_NUM_INT64)

struct c_json_value {
    uint32_t flags;

    // strings = string length
    // objects = number of pairs
    // arrays  = number of elements
    uint32_t count;

    const char * key;

    union {
        int64_t num_int64;
        double num_double;
        const char * str;
        struct c_json_value * first_value;
    };

    struct c_json_value * parent;
    struct c_json_value * prev;
    struct c_json_value * next;
};

// caller_memory is a preallocated section of
// memory that holds space for caller_memory_items * `struct c_json_value`
// If caller_memory is NULL or caller_memory_items is 0, malloc is used to
// allocated `struct c_json_value`s.
// If caller_memory_items * `struct c_json_value`s is allocated then
// allocating `struct c_json_value`s falls back to malloc.
// dup_strings determines if keys and string values are duplicated with
// malloc or if they are pointers into intext.
////
// when parsing keys and strings, the strings are not unescaped
bool c_json_parse_text(
    struct c_json_value * outvalue,
    const char * intext,
    void * caller_memory,
    uint32_t caller_memory_items,
    bool dup_strings);

// Same as above but instead of passing outvalue we just malloc() it...
struct c_json_value *
c_json_parse_text_ptr(
    const char * intext,
    void * caller_memory,
    uint32_t caller_memory_items,
    bool dup_strings);

// To free a value and such... and strings....
void c_json_free_tree(struct c_json_value * parent);

// Whether the value was malloc().
// If not then it's using memory the user passed in to c_json_parse_text().
bool c_json_is_malloc(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_MALLOC); }
// Whether strings are duplicated with malloc()
// or if they point into the `intext` value passed into c_json_parse_text().
bool c_json_is_dup_strings(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_DUP_STRINGS); }
// If a value is `null`...
bool c_json_is_null(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_NULL); }
// Whether a value is a boolean (JSON_FLAG_FALSE|JSON_FLAG_TRUE)...
bool c_json_is_boolean(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_BOOLEAN); }
// Whether a value is a number (int64 or double)
bool c_json_is_number(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_NUMBER); }
// If there's no decimal point in a number then we can make it an int64.
bool c_json_number_is_int64(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_NUM_INT64); }
// Opposite of the above ...
bool vjson_number_is_double(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_NUM_DOUBLE); }
// Yep.
bool c_json_is_string(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_STRING); }
// Yep.
bool c_json_is_array(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_ARRAY); }
// Yep.
bool c_json_is_object(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_OBJECT); }
// Yep.
bool c_json_boolean_is_false(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_FALSE); }
// Yep.
bool c_json_boolean_is_true(struct c_json_value * value)
{ return !!(value->flags & C_JSON_FLAG_TRUE); }
// Not necessary for you...
struct c_json_value * c_json_get_root(struct c_json_value * value)
{
    while (value->parent)
        value = value->parent;
    return value;
}

struct c_json_value * c_json_get_index(struct c_json_value * parent, uint32_t index)
{
    if (parent->count == 0)
        return NULL;

    if (index >= parent->count)
        return NULL;

    struct c_json_value * value = parent->first_value;

    if (index == 0)
        return value;

    for (uint32_t i = 0; i < index; i++)
        value = value->next;

    return value;
}

/////////////////////////////////////////////////
// Everything below is "internal stuff"
// The only real API stuff you need is above...
/////////////////////////////////////////////////

static inline bool c_json__char_is_insignificant_ws(const int c)
{ return (c == ' ' || c == '\t' || c == '\n' || c == '\r'); }

static inline bool is_hexadecimal_character(char c)
{
    return (c <= 'F' && c >= 'A')
        || (c <= 'f' && c >= 'a')
        || (c <= '9' && c >= '0');
}

static bool my_consume_str(const char ** text, const char * word)
{
    while (*word)
    {
        if (**text != *word++)
            return false;
        *text += 1;
    }

    return true;
}

static void c_json__consume_whitespace(const char ** text)
{
    while (1)
    {
        char c = **text;
        if (!c_json__char_is_insignificant_ws(c))
            break;
        *text += 1;
    }
}

static bool c_json__consume_string(
    const char ** intext,
    const char ** outstr, // ptr to start of malloc'd mem or start of str
    uint32_t * outlen,
    bool dup_strings)
{
    const char * str = *intext;
    // Haha never used because escaping + unicode decoding isn't fun
    //bool in_escape = false;
    //bool in_unicode = false;

    while (1)
    {
        char c = *str;

        // check for >=0 because char might be signed by default
        if (c >= 0 && c <= 0x1f) // control characters and NUL
            return false;

        if (c == '\\')
        {
            str += 1;
            switch (*str)
            {
                case '"': case '\\': case '/': case 'b':
                case 'f': case 'n': case 'r': case 't':
                    break;
                case 'u':
                    str += 1;
                    if (!is_hexadecimal_character(*str))
                        return false;
                    str += 1;
                    if (!is_hexadecimal_character(*str))
                        return false;
                    str += 1;
                    if (!is_hexadecimal_character(*str))
                        return false;
                    str += 1;
                    if (!is_hexadecimal_character(*str))
                        return false;
                    break;
                default:
                    return false;
            }
        }
        else if (c == '"')
        {
            uint32_t len = (uint32_t)(str - *intext);

            if (len)
            {
                if (dup_strings)
                {
                    char * str_mem = (char *)malloc(len + 1);

                    if (!str_mem)
                        return false;

                    memcpy(str_mem, *intext, len);
                    str_mem[len] = 0;

                    *outstr = str_mem;
                }
                else
                {
                    *((char *)str) = 0;
                    *outstr = *intext;
                }
            }
            else
            {
                *outstr = "";
            }

            *intext = str + 1;

            if (outlen)
                *outlen = len;

            return true;
        }

        str += 1;
    }
}

// Non-recursive free-er.
void c_json_free_tree(struct c_json_value * parent)
{
    if (parent == NULL)
        return;

    if (!c_json_is_array(parent) && !c_json_is_object(parent))
        return;

    struct c_json_value * cvalue = NULL;

    while (1)
    {
        if (cvalue)
        {
            if (cvalue->key && *cvalue->key && c_json_is_dup_strings(cvalue))
                free((char *)cvalue->key);

            if (c_json_is_malloc(cvalue))
                free(cvalue);
        }

        cvalue = parent->first_value;

        if (cvalue == NULL)
        {
            cvalue = parent;

            parent = parent->parent;

            if (parent == NULL)
                return;

            continue;
        }

        parent->first_value = cvalue->next;
        --parent->count;

        if (c_json_is_object(cvalue) || c_json_is_array(cvalue))
        {
            parent = cvalue;
            cvalue = NULL;
        }
        else
        {
            if (c_json_is_string(cvalue) && c_json_is_dup_strings(cvalue))
            {
                // Strings with 0 length aren't duplicated, just set to "";
                if (cvalue->str && cvalue->count)
                    free((char *)cvalue->str);
            }
        }
    }
}

// Overflow and underflow are unchecked, enjoy.
// Should be replaced with strtod().
static bool c_json__consume_number(
    const char ** intext,
    struct c_json_value * value)
{
    const char * text = *intext;
    unsigned i = 0, exponent = 0;

    bool is_negative = false;
    bool have_int_part = false;
    bool have_frac_part = false;
    bool have_frac_number = false;
    bool have_exp = false;
    bool have_exp_number = false;
    bool exp_is_negative = false;

    double num_double;
    double frac_divider = 10.0;
    int64_t num_int = 0;

    char c = text[i];

    // check for superfluous leading zero
    if (c == '0')
    {
        char AAA = text[i + 1];
        if (AAA <= '9' && AAA >= '0')
            return false;
    }

    if (c == '-')
    {
        is_negative = true;
        i += 1;
    }

    for ( ; ; i++)
    {
        c = text[i];

        if (!c)
            return false;

        if (c == '.')
        {
            if (!have_int_part || have_frac_part || have_exp)
                return false;

            have_frac_part = true;
            num_double = (double)num_int;
        }
        else if (c == 'E' || c == 'e')
        {
            if (have_exp || !have_int_part)
                return false;
            if (have_frac_part && !have_frac_number)
                return false;

            have_exp = true;

            char sign = text[i + 1];

            if (sign == '-' || sign == '+')
            {
                exp_is_negative = (sign == '-');
                i += 1;
            }
        }
        else if (c >= '0' && c <= '9')
        {
            if (have_exp)
            {
                have_exp_number = true;
                exponent *= 10;
                exponent += (unsigned)(c - '0');
            }
            else if (have_frac_part)
            {
                have_frac_number = true;
                num_double += ((double)(c - '0')) / frac_divider;
                frac_divider *= 10;
            }
            else
            {
                have_int_part = true;
                num_int = (num_int * 10) + (c - '0');
            }
        }
        else
        {
            if (!have_int_part)
                return false;
            if (have_frac_part && !have_frac_number)
                return false;
            if (have_exp && !have_exp_number)
                return false;

            // This is ugly.
            if (exponent != 0)
            {
                if (exp_is_negative)
                {
                    for (unsigned qqq = 0; qqq < exponent; qqq++)
                    {
                        if (have_frac_part)
                            num_double /= 10;
                        else
                        {
                            int64_t result = num_int / 10;
                            int64_t remainder = num_int - (result * 10);

                            if (remainder)
                            {
                                have_frac_part = true;
                                have_frac_number = true;
                                num_double = ((double)result);
                                num_double += ((double)remainder) / 10;
                            }
                            else
                                num_int = result;
                        }
                    }
                }
                else
                {
                    for (unsigned qqq = 0; qqq < exponent; qqq++)
                        if (have_frac_part)
                            num_double *= 10;
                        else
                            num_int *= 10;
                }
            }

            if (have_frac_part)
            {
                if (is_negative)
                    num_double = -num_double;

                value->flags |= C_JSON_FLAG_NUM_DOUBLE;
                value->num_double = num_double;
            }
            else
            {
                if (is_negative)
                    num_int = -num_int;

                value->flags |= C_JSON_FLAG_NUM_INT64;
                value->num_int64 = num_int;
            }

            *intext = &text[i];
            return true;
        }
    }
}

struct c_json_value * c_json__allocate_new_item(
    struct c_json_value * parent,
    struct c_json_value ** cmem,
    uint32_t * cmem_items)
{
    struct c_json_value * value = NULL;

    bool use_malloc = !(cmem_items && (*cmem_items > 0));

    if (use_malloc)
        value = (struct c_json_value *)malloc(sizeof(*value));
    else
    {
        --*cmem_items;
        value = *cmem++;
    }

    if (value)
    {
        memset(value, 0, sizeof(*value));
        value->parent = parent;
        if (use_malloc)
            value->flags |= C_JSON_FLAG_MALLOC;
        if (c_json_is_dup_strings(parent))
            value->flags |= C_JSON_FLAG_DUP_STRINGS;
    }

    return value;
}

static inline bool c_json__char_is_for_number(char c)
{ return (c == '-' || (c <= '9' && c >= '0')); }
static inline bool c_json__char_is_for_string(char c)
{ return (c == '"'); }
static inline bool c_json__char_is_for_opening_array_or_object(char c)
{ return (c == '[' || c == '{'); }
static inline bool c_json__char_is_for_true(char c)
{ return (c == 't'); }
static inline bool c_json__char_is_for_false(char c)
{ return (c == 'f'); }
static inline bool c_json__char_is_for_null(char c)
{ return (c == 'n'); }
static inline bool c_json__char_is_for_closing_array_or_object(char c)
{ return (c == ']' || c == '}'); }
static inline bool c_json__char_is_for_something(char c)
{
    return c_json__char_is_for_number(c)
        || c_json__char_is_for_string(c)
        || c_json__char_is_for_opening_array_or_object(c)
        || c_json__char_is_for_true(c)
        || c_json__char_is_for_false(c)
        || c_json__char_is_for_null(c)
        || c_json__char_is_for_closing_array_or_object(c);
}

// Non-recursive text parser.
static bool c_json__consume_text(
    const char ** intext,
    struct c_json_value * outvalue,
    struct c_json_value ** cmem,
    uint32_t * cmem_items)
{
    char c;
    bool have_key_need_value = false;
    const char * text = *intext;
    struct c_json_value * parent = outvalue;
    struct c_json_value * prev_value = NULL;
    struct c_json_value * new_value = NULL;

    while (1)
    {
        c_json__consume_whitespace(&text);

        c = *text;

        if (have_key_need_value)
        {
            if (c_json__char_is_for_closing_array_or_object(c))
                goto error__free_everything;
            have_key_need_value = false;
        }
        else
        {
            if (prev_value)
            {
                if (c == ',')
                {
                    text += 1;
                    c_json__consume_whitespace(&text);

                    c = *text;

                    // "[1,]"
                    if (c_json__char_is_for_closing_array_or_object(c))
                        goto error__free_everything;
                }
                else if (!c_json__char_is_for_closing_array_or_object(c))
                {
                    goto error__free_everything;
                }
            }

            if (!c_json__char_is_for_something(c))
                goto error__free_everything;

            if (!c_json__char_is_for_closing_array_or_object(c))
            {
                new_value = c_json__allocate_new_item(
                    parent,
                    cmem,
                    cmem_items
                );

                if (new_value == NULL)
                    goto error__free_everything;
            }
        }

        if (c_json__char_is_for_number(c))
        {
            if (!c_json__consume_number(&text, new_value))
                goto error__free_everything;
        }
        else if (c_json__char_is_for_string(c))
        {
            const char * out = NULL;
            uint32_t outlen = 0;

            text += 1;

            bool success = c_json__consume_string(
                &text,
                &out,
                &outlen,
                c_json_is_dup_strings(parent)
            );

            if (!success)
                goto error__free_everything;

            if (c_json_is_array(parent) || (new_value->key))
            {
                new_value->flags |= C_JSON_FLAG_STRING;
                new_value->count = outlen;
                new_value->str = out;
            }
            else
            {
                have_key_need_value = true;
                new_value->key = out;

                c_json__consume_whitespace(&text);

                if (*text != ':')
                    goto error__free_everything;

                text += 1;
            }
        }
        else if (c_json__char_is_for_opening_array_or_object(c))
        {
            new_value->flags |=
                (c == '[') ? C_JSON_FLAG_ARRAY : C_JSON_FLAG_OBJECT;

            text += 1;
        }
        else if (c_json__char_is_for_true(c))
        {
            if (!my_consume_str(&text, "true"))
                return false;

            new_value->flags |= C_JSON_FLAG_TRUE;
        }
        else if (c_json__char_is_for_false(c))
        {
            if (!my_consume_str(&text, "false"))
                return false;

            new_value->flags |= C_JSON_FLAG_FALSE;
        }
        else if (c_json__char_is_for_null(c))
        {
            if (!my_consume_str(&text, "null"))
                goto error__free_everything;

            new_value->flags |= C_JSON_FLAG_NULL;
        }
        else if (c_json__char_is_for_closing_array_or_object(c))
        {
            if (c_json_is_array(parent) != (c == ']'))
                goto error__free_everything;

            struct c_json_value * new_parent = parent->parent;

            if (new_parent == NULL)
            {
                text += 1;
                c_json__consume_whitespace(&text);

                if (*text)
                    goto error__free_everything;

                return true; // the end
            }

            parent = new_parent;

            if (parent->count)
                prev_value = c_json_get_index(parent, parent->count - 1);
            else
                prev_value = NULL;

            text += 1;
        }
        else
        {
            goto error__free_everything;
        }

        if (c_json__char_is_for_closing_array_or_object(c))
            continue;

        if (!have_key_need_value)
        {
            parent->count += 1;

            new_value->prev = prev_value;

            if (prev_value)
                prev_value->next = new_value;
            else
                parent->first_value = new_value;

            prev_value = new_value;
        }

        if (c_json__char_is_for_opening_array_or_object(c))
        {
            parent = new_value;
            prev_value = NULL;
        }

    } /* WHILE WHILE WHILE */

    /* UNREACHED UNREACHED UNREACHED */

error__free_everything:
    c_json_free_tree(c_json_get_root(parent));

    return false;
}

bool c_json_parse_text(
    struct c_json_value * outvalue,
    const char * intext,
    void * caller_memory,
    uint32_t caller_memory_items,
    bool dup_strings)
{
    struct c_json_value * cmem = (struct c_json_value *)caller_memory;
    uint32_t cmem_items = caller_memory_items;
    struct c_json_value ** cmem_ptr = &cmem;
    uint32_t * cmem_items_ptr = &cmem_items;

    if (!intext || !outvalue)
        return false;

    memset(outvalue, 0, sizeof(*outvalue));
    if (dup_strings)
        outvalue->flags |= C_JSON_FLAG_DUP_STRINGS;

    c_json__consume_whitespace(&intext);

    char c = *intext;

    if (c != '[' && c != '{')
        return false;

    outvalue->flags |= (c == '[') ? C_JSON_FLAG_ARRAY : C_JSON_FLAG_OBJECT;
    intext += 1;

    if (!caller_memory || !caller_memory_items)
    {
        cmem_ptr = NULL;
        cmem_items_ptr = NULL;
    }

    bool success = c_json__consume_text(
        &intext,
        outvalue,
        cmem_ptr,
        cmem_items_ptr
    );

    if (!success)
        memset(outvalue, 0, sizeof(*outvalue));

    return success;
}

struct c_json_value *
c_json_parse_text_ptr(
    const char * intext,
    void * caller_memory,
    uint32_t caller_memory_items,
    bool dup_strings)
{
    struct c_json_value * outvalue = (struct c_json_value *)malloc(sizeof(*outvalue));
    bool success = c_json_parse_text(outvalue, intext, caller_memory, caller_memory_items, dup_strings);
    if (!success) {
        free((void *)outvalue);
        outvalue = NULL;
    }
    return outvalue;
}


#ifdef __cplusplus
}
#endif

#endif // C_JSON_H
