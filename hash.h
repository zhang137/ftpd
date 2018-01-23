#ifndef HASH_H_INCLUDED
#define HASH_H_INCLUDED

#define HASH_ENTRY_INIT {0,NULL}
#define HASH_INIT {0,NULL}

struct hash_entry
{
    unsigned int hash_ip;
    struct hash_entry *next;
};

struct hash
{
    int alloc_size;
    struct hash_entry **hash_list;
};

void hash_func();

void init_hash();

void add_hash_entry();

void del_hash_entry();








#endif // HASH_H_INCLUDED
