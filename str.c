#include "str.h"
#include "sysutil.h"

void private_str_alloc_memchunk(struct mystr* p_str, const char* p_src,
                                unsigned int len)
{
    p_str->pbuf = sysutil_malloc(len);
    p_str->alloc_bytes = len;
    p_str->num_len = len;

    sysutil_memcpy(p_str->pbuf,p_src,len);
}
void str_alloc_text(struct mystr* p_str, const char* p_src)
{
    int len = sysutil_strlen(p_src);
    p_str->pbuf = sysutil_malloc(len);
    p_str->alloc_bytes = len;
    p_str->num_len = len;

    sysutil_memcpy(p_str->pbuf,p_src,len);
}
void str_alloc_alt_term(struct mystr* p_str, const char* p_src, char term)
{

}
void str_alloc_ulong(struct mystr* p_str, unsigned long the_ulong)
{
    int ulong_size = sizeof(unsigned long);
    p_str->pbuf = sysutil_malloc(ulong_size);
    p_str->alloc_bytes = ulong_size;
    p_str->num_len = ulong_size;

    sysutil_memcpy(p_str->pbuf,&the_ulong,ulong_size);
}
void str_alloc_filesize_t(struct mystr* p_str, filesize_t the_filesize)
{
     int filesize = sizeof(filesize_t);
    p_str->pbuf = sysutil_malloc(filesize);
    p_str->alloc_bytes = filesize;
    p_str->num_len = filesize;

    sysutil_memcpy(p_str->pbuf,&the_filesize,filesize);
}
void str_copy(struct mystr* p_dest, const struct mystr* p_src)
{
    sysutil_memcpy(p_dest->pbuf,p_src->pbuf,p_src->num_len);
}

const char* str_strdup(const struct mystr* p_str)
{
    return strdup(p_str->pbuf);
}
void str_empty(struct mystr* p_str)
{
    sysutil_memclr(p_str->pbuf,p_str->num_len);
}
void str_free(struct mystr* p_str)
{
    p_str->alloc_bytes = 0;
    p_str->num_len = 0;
    sysutil_free(p_str->pbuf);
}
void str_trunc(struct mystr* p_str, unsigned int trunc_len)
{
    sysutil_memclr(p_str->pbuf,trunc_len);
    p_str->num_len = 0;
}
void str_reserve(struct mystr* p_str, unsigned int res_len)
{
    p_str->pbuf = sysutil_malloc(res_len);
    p_str->alloc_bytes = res_len;
}

int str_isempty(const struct mystr* p_str)
{
    return p_str->num_len == 0;
}
unsigned int str_getlen(const struct mystr* p_str)
{
    return p_str->num_len;
}
const char* str_getbuf(const struct mystr* p_str)
{
    return (const char *)p_str->pbuf;
}sysutil_memcpy

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
    return (int)(ptr1_size - ptr2_size);

}
int str_equal(const struct mystr* p_str1, const struct mystr* p_str2)
{
    return (str_strcmp(p_str1,p_str2) == 0);
}
int str_equal_text(const struct mystr* p_str, const char* p_text)
{
    unsigned int ptext_len = sysutil_strlen(p_text);
    return (str_equal_internal(p_str->pbuf,p_str->num_len,p_text,ptext_len) == 0);
}
void str_append_str(struct mystr* p_str, const struct mystr* p_other)
{
    int num_len = p_str->num_len;
    int append_len = p_str->alloc_bytes - num_len;
    append_len = min(append_len,p_other->num_len);
    p_str->num_len += append_len;
    sysutil_memcpy(p_str->pbuf+num_len,p_other->pbuf,append_len);
}
void str_append_text(struct mystr* p_str, const char* p_src)
{
    int num_len = p_str->num_len;
    int append_len = p_str->alloc_bytes - num_len;
    append_len = min(append_len,p_other->num_len);
    p_str->num_len += append_len;
    sysutil_memcpy(p_str->pbuf+num_len,p_other->pbuf,append_len);

}
void str_append_ulong(struct mystr* p_str, unsigned long the_long) /// ?????
{
    int num_len = p_str->num_len;
    int ulong_size = sizeof(unsigned long);
    int append_len = p_str->alloc_bytes - num_len;
    if(append_len < ulong_size) return;
    p_str->num_len += ulong_size;
    sysutil_memcpy(p_str->pbuf+num_len,the_long,ulong_size);
}

void str_append_filesize_t(struct mystr* p_str, filesize_t the_filesize)
{
    int num_len = p_str->num_len;
    int filesize_t_size = sizeof(filesize_t);
    int append_len = p_str->alloc_bytes - num_len;
    if(append_len < filesize_t_size) return;
    p_str->num_len += filesize_t_size;
    sysutil_memcpy(p_str->pbuf+num_len,the_long,filesize_t_size);
}

void str_append_char(struct mystr* p_str, char the_char)
{
    int num_len = p_str->num_len;
    int char_size = sizeof(the_char);
    int append_len = p_str->alloc_bytes - num_len;
    if(append_len < char_size) return;
    p_str->num_len += char_size;
    sysutil_memcpy(p_str->pbuf+num_len,the_char,char_size);
}

void str_append_double(struct mystr* p_str, double the_double)
{
    int num_len = p_str->num_len;
    int double_size = sizeof(the_double);
    int append_len = p_str->alloc_bytes - num_len;
    if(append_len < double_size) return;
    p_str->num_len += double_size;
    sysutil_memcpy(p_str->pbuf+num_len,the_char,double_size);
}

void str_upper(struct mystr* p_str)
{
    int i;
    for(i = 0; i < p_str->num_len; i++)
    {
        p_str->pbuf[i] = sysutil_toupper(p_str->pbuf[i]);
    }
}

void str_rpad(struct mystr* p_str, const unsigned int min_width)
{
    int adjust_len = p_str->alloc_bytes + min_width
    char *tmp = (char *)sysutil_malloc(adjust_len);
    sysutil_memcpy(tmp+min_width,p_str->pbuf,p_str->num_len);
    sysutil_free(p_str->pbuf);
    p_str->pbuf = tmp;
    p_str->alloc_bytes = adjust;
}

void str_lpad(struct mystr* p_str, const unsigned int min_width)
{
    int adjust_len = p_str->alloc_bytes + min_width
    char *tmp = (char *)sysutil_malloc(adjust_len);
    sysutil_memcpy(tmp+min_width,p_str->pbuf,p_str->num_len);
    sysutil_free(p_str->pbuf);
    p_str->pbuf = tmp;
    p_str->alloc_bytes = adjust;
}

void str_replace_char(struct mystr* p_str, char from, char to)
{
    p_str->pbuf[from] = to;
}

void str_replace_text(struct mystr* p_str, const char* p_from,
                      const char* p_to)
{

}

void str_split_char(struct mystr* p_src, struct mystr* p_rhs, char c)
{
    int ipos, i,surplus_size;
    int str_len = p_src->num_len;
    for(ipos = 0; ipos < str_len; ipos++)
    {
        if(p_src[ipos] == c)
            break;
    }

    surplus_size = str_len - ipos - 1;
    if(surplus_size > 0)
    {
        p_rhs.pbuf = sysutil_malloc(surplus_size);
        sysutil_memcpy(p_rhs.pbuf,p_src->pbuf+ipos+1,surplus_size);
        p_rhs.num_len = p_rhs.alloc_bytes = surplus_size;

        sysutil_memclr(p_src->pbuf+iops,surplus_size+1);
        p_src->num_len = ipos;
    }
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
