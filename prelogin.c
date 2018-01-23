#include <stdio.h>
#include "prelogin.h"
#include "sysutil.h"
#include "str.h"

void init_connection(struct ftpd_session *session)
{
    struct mystr str_cmd = INIT_MYSTR;
    struct mystr str_arg = INIT_MYSTR;
    while(1)
    {
        str_cmd = get_cmd_from_client(&str_arg);
        if(str_equal_text(&str_cmd,"USER") {

        }
        else(str_equal_text(&str_cmd,"PASS")) {

        }else {
            write_cmd_respond(FTP_CMDWRIO,FTP_LOGINERR,"Please login with USER and PASS.");
        }
    }
}

struct mystr get_cmd_from_client(struct mystr *str_arg)
{
    int nread,end_point;
    char term = '\n';
    const char *p_src = NULL;
    struct mystr str_line = INIT_MYSTR;
    struct mystr str_cmd  =  INIT_MYSTR;

    nread = get_netdata(&str_line,&end_point,term);

    if(str_get_char_at(&str_line,nread-1) == '\r'
        str_alloc_alt_term(&str_cmd,str_line.pbuf,'\0');

    str_split_char(&str_cmd,arg_str,' ');
    str_upper(&str_cmd);
    return str_cmd;
//    if(str_contains_unprintable(&str_line) || !str_contains_space(&str_line))
//    {
//        write_cmd_respond(FTP_CMDWRIO,FTP_LOGINERR,"BAD COMMAND!");
//    }
//    p_src = str_getbuf(&str_line);
};
