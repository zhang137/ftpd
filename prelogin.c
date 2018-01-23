#include <stdio.h>
#include "prelogin.h"
#include "sysutil.h"
#include "str.h"

void init_connection()
{
    struct mystr cmd_arg_str;
    while(1)
    {
        cmd_arg_str = get_cmd_from_client();

        if(1)
        {

        }
    }
}

struct mystr get_cmd_from_client()
{
    int nread,end_point;
    char term = '\n';
    const char *p_src = NULL;
    struct mystr str_line = INIT_MYSTR;
    struct mystr str_arg  =  INIT_MYSTR;
    struct mystr str_cmd  =  INIT_MYSTR;

    nread = get_netdata(&str_line,&end_point,term);
    if(str_get_char_at(&str_line,nread-1) != '\r'
       str_contains_unprintable(&str_line) || str_all_space(&str_line))
    {
        write_cmd_respond(FTP_CMDWRIO,FTP_BADCMD,"BAD COMMAND!");
    }
    p_src = str_getbuf(&str_line);
    str_alloc_alt_term()




};
