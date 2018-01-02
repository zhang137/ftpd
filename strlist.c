#include <stdlib.h>

#include "strlist.h"


void str_list_free(struct mystr_list* p_list)
{

}

void str_list_add(struct mystr_list* p_list, const struct mystr* p_str)
{

    if(p_list->list_len == p_list->alloc_len)
    {
        if(p_list->alloc_len == 0)
        {
            p_list->alloc_len = 32;
            p_list->pnodes = (struct mystr*)sysutil_malloc(p_list->alloc_len *
                                                   sizeof(struct mystr));
        }
        else
        {
            p_list->alloc_len *= 2;
            p_list->pnodes = (struct mystr*)realloc(p_list->pnodes,p_list->alloc_len);
        }
    }

    str_strcmp(&(p_list->pnodes[p_list->list_len]),p_str);
    p_list->list_len += 1;

}
//void str_list_sort(struct mystr_list* p_list, int reverse)
//{
//
//}

unsigned int str_list_get_length(const struct mystr_list* p_list)
{
    if(p_list)
    return p_list->list_len;
}

int str_list_contains_str(const struct mystr_list* p_list,
                          const struct mystr* p_str)
{
    struct mystr *pTemp = p_list;
    for(int i = 0; i < p_list->list_len; i++)
    {
        //if()
    }
    return 0;
}

const struct mystr* str_list_get_pstr(const struct mystr_list* p_list,
                                      unsigned int index)
{

}
