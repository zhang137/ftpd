#ifndef STRLIST_H_INCLUDED
#define STRLIST_H_INCLUDED

struct mystr_list
{
  unsigned int PRIVATE_HANDS_OFF_alloc_len;
  unsigned int PRIVATE_HANDS_OFF_list_len;
  struct mystr_list_node* PRIVATE_HANDS_OFF_p_nodes;
};


#define INIT_STRLIST \
  { 0, 0, (void*)0 }

void str_list_free(struct mystr_list* p_list);

void str_list_add(struct mystr_list* p_list, const struct mystr* p_str,
                  const struct mystr* p_sort_key_str);

void str_list_sort(struct mystr_list* plist, int reverse);

unsigned int str_list_get_length(const struct mystr_list* p_list);
int str_list_contains_str(const struct mystr_list* p_list,
                          const struct mystr* p_str);

const struct mystr* str_list_get_pstr(const struct mystr_list* p_list,
                                      unsigned int indexx);

#endif // STRLIST_H_INCLUDED
