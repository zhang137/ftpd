#include <stdio.h>
#include <stdlib.h>
#include "session.h"

#include "str.h"

int main()
{
    struct mystr str1 = INIT_MYSTR;
    private_str_alloc_memchunk(&str1,"1234512345s",11);

    struct mystr str2 = INIT_MYSTR;
   // private_str_alloc_memchunk(&str1,"str",3);

    str_split_char(&str1,&str2,'s');

    return 0;
}
