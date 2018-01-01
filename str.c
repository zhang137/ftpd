#include "str.h"
#include "sysutil.h"

void private_str_alloc_memchunk(struct mystr* p_str, const char* p_src,
                                unsigned int len)
{

}
void str_alloc_text(struct mystr* p_str, const char* p_src)
{

}
void str_alloc_alt_term(struct mystr* p_str, const char* p_src, char term)
{

}
void str_alloc_ulong(struct mystr* p_str, unsigned long the_ulong)
{

}
void str_alloc_filesize_t(struct mystr* p_str, filesize_t the_filesize)
{

}
void str_copy(struct mystr* p_dest, const struct mystr* p_src)
{
}

const char* str_strdup(const struct mystr* p_str)
{

}
void str_empty(struct mystr* p_str)
{
}
void str_free(struct mystr* p_str)
{
}
void str_trunc(struct mystr* p_str, unsigned int trunc_len)
{
}
void str_reserve(struct mystr* p_str, unsigned int res_len)
{
}

int str_isempty(const struct mystr* p_str)
{
}
unsigned int str_getlen(const struct mystr* p_str)
{
}
const char* str_getbuf(const struct mystr* p_str)
{
}

int str_strcmp(const struct mystr* p_str1, const struct mystr* p_str2)
{
    return str_equal_internal(p_str1->pbuf,p_str2->pbuf,p_str1->num_len,p_str2->num_len);
}
int str_equal_internal(const char *p_ptr1,unsigned int ptr1_size,
                       const char *p_ptr2,unsigned int ptr2_size)
{
    int result;
    int min_size = ptr1_size;

    if(ptr2_size < min_size)
    {
        min_size = ptr2_size;
    }

    result = sysutil_memcmp(p_ptr1,p_ptr2,min_size);
    if(result != 0 || ptr1_size == ptr2_size)
    {
        return result;
    }
    return (int)(ptr1_size - ptr2_size)

}
int str_equal(const struct mystr* p_str1, const struct mystr* p_str2)
{
    return (str_strcmp(p_str1,p_str2) == 0);
}
int str_equal_text(const struct mystr* p_str, const char* p_text)
{
    unsigned int ptext_len = sysutil_strlen(p_text);
    return (str_equal_internal(p_str->pbuf,p_str->num_len,p_str2,ptext_len) == 0);
}
void str_append_str(struct mystr* p_str, const struct mystr* p_other)
{
}
void str_append_text(struct mystr* p_str, const char* p_src)
{
}
void str_append_ulong(struct mystr* p_str, unsigned long the_long)
{
}
void str_append_filesize_t(struct mystr* p_str, filesize_t the_filesize)
{
}
void str_append_char(struct mystr* p_str, char the_char)
{
}
void str_append_double(struct mystr* p_str, double the_double)
{
}

void str_upper(struct mystr* p_str)
{
}
void str_rpad(struct mystr* p_str, const unsigned int min_width)
{
}
void str_lpad(struct mystr* p_str, const unsigned int min_width)
{
}
void str_replace_char(struct mystr* p_str, char from, char to)
{
}
void str_replace_text(struct mystr* p_str, const char* p_from,
                      const char* p_to)
{
}

void str_split_char(struct mystr* p_src, struct mystr* p_rhs, char c)
{
}
void str_split_char_reverse(struct mystr* p_src, struct mystr* p_rhs, char c)
{
}
void str_split_text(struct mystr* p_src, struct mystr* p_rhs,
                    const char* p_text)
{
}
void str_split_text_reverse(struct mystr* p_src, struct mystr* p_rhs,
                            const char* p_text)
{
}
struct str_locate_result str_locate_char(
  const struct mystr* p_str, char look_char)
{
}
struct str_locate_result str_locate_str(
  const struct mystr* p_str, const struct mystr* p_look_str)
{
}
struct str_locate_result str_locate_str_reverse(
  const struct mystr* p_str, const struct mystr* p_look_str)
{
}
struct str_locate_result str_locate_text(
  const struct mystr* p_str, const char* p_text)
{
}
struct str_locate_result str_locate_text_reverse(
  const struct mystr* p_str, const char* p_text)
{
}
struct str_locate_result str_locate_chars(
  const struct mystr* p_str, const char* p_chars)
{
}

void str_left(const struct mystr* p_str, struct mystr* p_out,
              unsigned int chars)
{
}
void str_right(const struct mystr* p_str, struct mystr* p_out,
               unsigned int chars)
{
}
void str_mid_to_end(const struct mystr* p_str, struct mystr* p_out,
                    unsigned int indexx)
{
}

char str_get_char_at(const struct mystr* p_str, const unsigned int indexx)
{
}
int str_contains_space(const struct mystr* p_str)
{
}
int str_all_space(const struct mystr* p_str)
{
}
int str_contains_unprintable(const struct mystr* p_str)
{
}
void str_replace_unprintable(struct mystr* p_str, char new_char)
{
}
int str_atoi(const struct mystr* p_str)
{
}
filesize_t str_a_to_filesize_t(const struct mystr* p_str)
{
}
unsigned int str_octal_to_uint(const struct mystr* p_str)
{
}

int str_getline(const struct mystr* p_str, struct mystr* p_line_str,
                unsigned int* p_pos)
{

}

int str_contains_line(const struct mystr* p_str,
                      const struct mystr* p_line_str)
{

}
