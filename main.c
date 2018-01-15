#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include "session.h"
#include "twoprocess.h"
#include "sysutil.h"
#include "prelogin.h"
#include "str.h"
#include "strlist.h"
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{

    struct mystr_list *pstr_list = INIT_STRLIST;
    pstr_list = (struct mystr_list *)sysutil_malloc(sizeof(struct mystr_list));

    struct mystr str1;
    str1.pbuf = sysutil_malloc(100);
    sysutil_memclr(str1.pbuf,100);
    str1.alloc_bytes = 100;
    sysutil_memcpy(str1.pbuf,"Hello World\n",12);
    str1.num_len = 12;

    struct mystr str2;
    str2.pbuf = sysutil_malloc(100);
    sysutil_memclr(str2.pbuf,100);
    str2.alloc_bytes = 100;
    sysutil_memcpy(str2.pbuf,"Hello Test\n",11);
    str2.num_len = 11;

    struct mystr str3;
    str3.pbuf = sysutil_malloc(100);
    sysutil_memclr(str3.pbuf,100);
    str3.alloc_bytes = 100;
    sysutil_memcpy(str3.pbuf,"World Hello\n",12);
    str3.num_len = 12;


    str_list_add(pstr_list,&str1);
    str_list_add(pstr_list,&str2);
    str_list_add(pstr_list,&str3);

    int i = 0;
    printf("%d\n",pstr_list->list_len);
    for(; i < pstr_list->list_len; i++)
    {
        struct mystr *tmp = str_list_get_pstr(pstr_list,i);
        printf("%s",tmp->pbuf);
    }

    str_list_free(pstr_list);

    pid_t pid;
    int fd, logfd;
    struct ftpd_session session;
    session.idle_timeout = 20;
    session.data_timeout = 30;
    session.is_anonymous = 0;

    sysutil_deamon();




    return 0;
}
