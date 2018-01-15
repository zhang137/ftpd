#include <stdlib.h>

#include "strlist.h"


void str_list_free(struct mystr_list* p_list)
{
    int i;
    struct mystr_list *tmp = p_list;
    for(i = 0; i < p_list->list_len; i++)
    {
        struct mystr *pstr = tmp->pnodes + i;
        if(pstr != NULL)
            sysutil_free(pstr->pbuf);
    }
    sysutil_free(p_list->pnodes);
    sysutil_free(p_list);
    tmp->list_len = 0;
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
            p_list->pnodes = (struct mystr*)sysutil_realloc(p_list->pnodes,p_list->alloc_len);
        }
    }

    sysutil_memcpy(&(p_list->pnodes[p_list->list_len]),p_str,sizeof(struct mystr));
    p_list->list_len += 1;

}
//void str_list_sort(struct mystr_list* p_list, int reverse)
//{
//
//}

unsigned int str_list_get_length(const struct mystr_list* p_list)
{
    return p_list->list_len;
}

int str_list_contains_str(const struct mystr_list* p_list,
                          const struct mystr* p_str)
{
    int i;
    struct mystr_list *pTemp = p_list;
    for(i = 0; i < p_list->list_len; i++)
    {
        struct mystr *pstr = pTemp->pnodes + i;
        if(pstr == p_str)
            return 1;
    }
    return 0;
}

const struct mystr* str_list_get_pstr(const struct mystr_list* p_list,
                                      unsigned int index)
{
    if(index < 0 || index >= p_list->list_len)
        return NULL;
    struct mystr_list *pTemp = p_list;
    return pTemp->pnodes + index;
}
