#ifndef STRLIST_H_INCLUDED
#define STRLIST_H_INCLUDED

#include <netinet/in.h>
#include "str.h"

struct mystr_list
{
  unsigned int alloc_len;
  unsigned int list_len;
  struct mystr* pnodes;
};


#define INIT_STRLIST \
  { 0, 0, (void*)0 }

void str_list_free(struct mystr_list* p_list);

void str_list_add(struct mystr_list* p_list, const struct mystr* p_str);

//void str_list_sort(struct mystr_list* p_list, int reverse);

unsigned int str_list_get_length(const struct mystr_list* p_list);
int str_list_contains_str(const struct mystr_list* p_list,
                          const struct mystr* p_str);

const struct mystr* str_list_get_pstr(const struct mystr_list* p_list,
                                      unsigned int indexx);

#endif // STRLIST_H_INCLUDED
