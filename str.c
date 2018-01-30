#include <stdio.h>
#include "str.h"
#include "sysutil.h"
#include <syslog.h>

void private_str_alloc_memchunk(struct mystr* p_str, const char* p_src,
                                unsigned int len)
{
    p_str->pbuf = (char *)sysutil_malloc(len+1);
    p_str->alloc_bytes = len+1;
    p_str->num_len = 0;

    sysutil_memclr(p_str->pbuf,len+1);
    if(p_src != NULL && (p_str->num_len = sysutil_strlen(p_src)))
    {
        sysutil_memcpy(p_str->pbuf,p_src,p_str->num_len);
    }
}

void str_alloc_text(struct mystr* p_str, const char* p_src)
{
    if(p_src == NULL)
        die("got null strings");

    int len = sysutil_strlen(p_src);
    p_str->pbuf = (char *)sysutil_malloc(len+1);
    p_str->alloc_bytes = len+1;
    p_str->num_len = len;

    sysutil_memclr(p_str->pbuf,len+1);
    sysutil_memcpy(p_str->pbuf,p_src,len);
}

void str_alloc_alt_term(struct mystr* p_str, const char* p_src, char term)
{
    int strlen = sysutil_strlen(p_src);
    private_str_alloc_memchunk(p_str,p_src,strlen);
    p_str->pbuf[strlen-1] = term;
    //str_replace_char(p_str,'\r','\0');
    p_str->num_len -= 1;

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
    p_str->num_len = 0;
}

void str_free(struct mystr* p_str)
{
    p_str->alloc_bytes = 0;
    p_str->num_len = 0;
    sysutil_free(p_str->pbuf);
    p_str->pbuf = NULL;
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
    return (int)(ptr1_size - ptr2_size);

}
int str_equal(const struct mystr* p_str1, const struct mystr* p_str2)
{
    return (str_strcmp(p_str1,p_str2) == 0);
}
int str_equal_text(const struct mystr* p_str, const char* p_text)
{
    unsigned int text_len = sysutil_strlen(p_text);
    unsigned int str_len = sysutil_strlen(p_str->pbuf);
    return (str_equal_internal(p_str->pbuf,str_len,p_text,text_len) == 0);
}
void str_append_str(struct mystr* p_str, const struct mystr* p_other)
{
    int num_len = p_str->num_len;
    int append_len = p_other->num_len;
    int left_len = p_str->alloc_bytes - num_len;
    if(left_len < append_len)
    {
        str_rpad(p_str,append_len-left_len+1);
    }

    sysutil_memcpy(p_str->pbuf+num_len,p_other->pbuf,append_len);
    p_str->num_len += append_len;
}

void str_append_text(struct mystr* p_str, const char* p_src)
{
    int num_len = p_str->num_len;
    int append_len = sysutil_strlen(p_src);
    int left_len = p_str->alloc_bytes - num_len;
    if(left_len < append_len)
    {
        str_rpad(p_str,append_len-left_len+1);
    }

    sysutil_memcpy(p_str->pbuf+num_len,p_src,append_len);
    p_str->num_len += append_len;
}
void str_append_ulong(struct mystr* p_str, unsigned long the_long)
{
    int num_len = p_str->num_len;
    int ulong_size = sizeof(unsigned long);
    int left_len = p_str->alloc_bytes - num_len;
    if(left_len < ulong_size)
    {
         str_rpad(p_str,ulong_size - left_len);
    }

    sysutil_memcpy(p_str->pbuf+num_len,&the_long,ulong_size);
    p_str->num_len += ulong_size;
}

void str_append_filesize_t(struct mystr* p_str, filesize_t the_filesize)
{
    int num_len = p_str->num_len;
    int filesize_t_size = sizeof(filesize_t);
    int left_len = p_str->alloc_bytes - num_len;
    if(left_len < filesize_t_size)
    {
        str_rpad(p_str,filesize_t_size - left_len);
    }

    sysutil_memcpy(p_str->pbuf+num_len,&the_filesize,filesize_t_size);
    p_str->num_len += filesize_t_size;
}

void str_append_char(struct mystr* p_str, char the_char)
{
    int num_len = p_str->num_len;
    int char_size = sizeof(char);
    int left_len = p_str->alloc_bytes - num_len;

    if(left_len <= char_size)
    {
        str_rpad(p_str,1);
    }

    sysutil_memcpy(p_str->pbuf+num_len,&the_char,char_size);

    if(the_char != '\0')
        p_str->num_len += char_size;
}

void str_append_double(struct mystr* p_str, double the_double)
{
    int num_len = p_str->num_len;
    int double_size = sizeof(the_double);
    int left_len = p_str->alloc_bytes - num_len;
    if(left_len < double_size)
    {
        str_rpad(p_str,double_size-left_len);
    }
    sysutil_memcpy(p_str->pbuf+num_len,&the_double,double_size);
    p_str->num_len += double_size;
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
    int adjust_len = p_str->alloc_bytes + min_width;
    void *ptr_tmp = sysutil_malloc(adjust_len);

    sysutil_memclr(ptr_tmp,adjust_len);
    sysutil_memcpy(ptr_tmp,p_str->pbuf,p_str->num_len);
    sysutil_free(p_str->pbuf);

    p_str->pbuf = ptr_tmp;
    p_str->alloc_bytes = adjust_len;
}

void str_lpad(struct mystr* p_str, const unsigned int min_width)
{
    int adjust_len = p_str->alloc_bytes + min_width;
    void *ptr_tmp = sysutil_malloc(adjust_len);
    sysutil_memclr(ptr_tmp,adjust_len);
    sysutil_memcpy(ptr_tmp+min_width,p_str->pbuf,p_str->num_len);
    sysutil_free(p_str->pbuf);
    p_str->pbuf = ptr_tmp;
    p_str->alloc_bytes = adjust_len;
}

void str_replace_char(struct mystr* p_str, char from, char to)
{
    int i;
    for(i = 0; i < p_str->num_len; i++)
    {
        if(p_str->pbuf[i] == from)
            p_str->pbuf[i] = to;
    }
}

void str_replace_text(struct mystr* p_str, const char* p_from,
                      const char* p_to)
{

}

void str_split_char(struct mystr* p_src, struct mystr* p_rhs, char c)
{
    int ipos,surplus_size;
    int str_len = p_src->num_len;
    for(ipos = 0; ipos < str_len; ipos++)
    {
        if(p_src->pbuf[ipos] == c)
            break;
    }
    //12345c12345
    surplus_size = str_len - ipos - 1;
    if(surplus_size > 0)
    {
        p_rhs->pbuf = sysutil_malloc(surplus_size+1);
        sysutil_memclr(p_rhs->pbuf,surplus_size+1);
        p_rhs->alloc_bytes = surplus_size+1;
        p_rhs->num_len = surplus_size;

        sysutil_memcpy(p_rhs->pbuf,p_src->pbuf+ipos+1,surplus_size);
    }
    sysutil_memclr(p_src->pbuf+ipos,surplus_size+1);
    p_src->num_len = ipos;
}

void str_split_char_reverse(struct mystr* p_src, struct mystr* p_rhs, char c)
{
    int ipos,surplus_size;
    int str_len = p_src->num_len;
    for(ipos = str_len - 1; ipos >= 0; ipos--)
    {
        if(p_src->pbuf[ipos] == c)
            break;
    }
    //12345s12345
    surplus_size = str_len - ipos - 1;
    if(surplus_size > 0)
    {
        p_rhs->pbuf = sysutil_malloc(surplus_size+1);
        sysutil_memclr(p_rhs->pbuf,surplus_size+1);
        p_rhs->alloc_bytes = surplus_size+1;
        p_rhs->num_len = surplus_size;

        sysutil_memcpy(p_rhs->pbuf,p_src->pbuf+ipos+1,surplus_size);
    }
    sysutil_memclr(p_src->pbuf+ipos,str_len-ipos);
    p_src->num_len = ipos;
}

void str_split_text(struct mystr* p_src, struct mystr* p_rhs,
                    const char* p_text)
{
    int ipos,jpos,kpos,surplus_size;
    int src_len = p_src->num_len;
    int match_len = sysutil_strlen(p_text);

    if(!p_text[0]) return;

    for(ipos = 0; ipos < src_len; ipos++)
    {
        for(jpos = 0,kpos = ipos; p_src->pbuf[kpos] == p_text[jpos]
                     && p_text[jpos] != '\0'; kpos++,jpos++) ;
        if(!p_text[jpos]) break;
    }
    surplus_size = src_len - match_len - ipos;

    if(surplus_size)
    {

        p_rhs->pbuf = (char *)sysutil_malloc(surplus_size);
        p_rhs->alloc_bytes = surplus_size;
        p_rhs->num_len = surplus_size;
        sysutil_memcpy(p_rhs->pbuf, p_src->pbuf+ipos+match_len, surplus_size);
    }

    sysutil_memclr(p_src->pbuf+ipos,match_len+surplus_size);
    p_src->num_len = ipos;

}

void str_split_text_reverse(struct mystr* p_src, struct mystr* p_rhs,
                            const char* p_text)
{
    int ipos,jpos,kpos,surplus_size;
    int src_len = p_src->num_len;
    int match_len = sysutil_strlen(p_text);

    if(!p_text[0]) return;
    for(ipos = src_len-match_len+1; ipos > 0; ipos--)
    {
        for(jpos = 0,kpos = ipos; p_src->pbuf[kpos] == p_text[jpos]
                     && p_text[jpos] != '\0'; kpos++,jpos++) ;
        if(!p_text[jpos]) break;
    }
    //1234567str1234
    surplus_size = src_len - match_len - ipos;
    if(surplus_size > 0)
    {
        p_rhs->pbuf = (char *)sysutil_malloc(surplus_size);
        p_rhs->alloc_bytes = surplus_size;
        p_rhs->num_len = surplus_size;
        sysutil_memcpy(p_rhs->pbuf, p_src->pbuf+ipos+match_len, surplus_size);
    }

    sysutil_memclr(p_src->pbuf+ipos,match_len+surplus_size);
    p_src->num_len = ipos;
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
    if(chars <= 0 ) return;
    if (chars > p_str->num_len)
        chars = p_str->num_len;

    p_out->pbuf = sysutil_malloc(chars);
    p_out->alloc_bytes = p_out->num_len = chars;
    sysutil_memcpy(p_out->pbuf,p_str->pbuf,chars);
}
void str_right(const struct mystr* p_str, struct mystr* p_out,
               unsigned int chars)
{
    if (chars > p_str->num_len)
        chars = p_str->num_len;

    int index = p_str->num_len - chars;
    private_str_alloc_memchunk(p_out,p_str->pbuf+index,chars);

}
void str_mid_to_end(const struct mystr* p_str, struct mystr* p_out,
                    unsigned int indexx)
{
    //12356
    int len = p_str->num_len - indexx;
    p_out->pbuf = sysutil_malloc(len);
    p_out->alloc_bytes = p_out->num_len = len;
    sysutil_memcpy(p_out->pbuf,p_str->pbuf+indexx,len);
}

char str_get_char_at(const struct mystr* p_str, const unsigned int indexx)
{
    return (char)p_str->pbuf[indexx];
}
int str_contains_space(const struct mystr* p_str)
{
    int i;
    for(i = 0; i < p_str->num_len; i++)
    {
        if(sysutil_isspace(str_get_char_at(p_str,i)))
            return 1;
    }
    return 0;
}
int str_all_space(const struct mystr* p_str)
{
    return str_isempty(p_str);
}

struct mystr str_wipeout_blank(struct mystr *p_str)
{
    int pos;
    int strlen = str_getlen(p_str);
    struct mystr strbuf = INIT_MYSTR;

    for(pos = 0; pos < strlen; pos++)
    {
        if(!sysutil_isspace(str_get_char_at(p_str,pos)))
            break;
    }

    str_right(p_str,&strbuf,strlen - pos);
    str_free(p_str);

    return strbuf;
}


int str_contains_unprintable(const struct mystr* p_str)
{
    int i;
    for(i = 0; i < p_str->num_len; i++)
    {
    if(!sysutil_isprint(p_str->pbuf[i]))
            return 1;
    }

    return 0;
}
void str_replace_unprintable(struct mystr* p_str, char new_char)
{
    int i;
    if(p_str->num_len > 0)
    {
        for(i = 0; i < p_str->num_len; i++)
        {
            if(!sysutil_isprint(p_str->pbuf[i]))
                p_str->pbuf[i] = new_char;
        }
    }

}
int str_atoi(const struct mystr* p_str)
{
    //return atoi(p_str->pbuf);
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
    //123456
    int ipos;
    int src_len = p_str->num_len;
    for (ipos = 0; ipos < src_len; ipos++)
    {
        if(p_str->pbuf[ipos] == '\n')
        {
            break;
        }
    }
    if(ipos < src_len)
    {
        //123\r\n
        p_line_str->pbuf = sysutil_malloc(ipos+1);
        p_line_str->num_len = p_line_str->alloc_bytes = ipos;
        sysutil_memclr(p_line_str->pbuf,ipos+1);
        sysutil_memcpy(p_line_str->pbuf,p_str->pbuf,ipos);
        *p_pos = ipos;
        return 1;
    }
    return 0;
}

int str_contains_line(const struct mystr* p_str,
                      const struct mystr* p_line_str)
{

}
