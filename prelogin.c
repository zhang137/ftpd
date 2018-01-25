#include <stdio.h>
#include <syslog.h>
#include "sysutil.h"
#include "prelogin.h"
#include "ftpcode.h"
#include "commoncode.h"
#include "ftpcmd.h"

void init_connection(struct ftpd_session *session)
{
    struct mystr str_cmd = INIT_MYSTR;
    struct mystr str_arg = INIT_MYSTR;

    while(1)
    {
        str_cmd = get_rpc_request(&str_arg);
        sysutil_syslog(str_cmd.pbuf,LOG_USER | LOG_INFO);
        sysutil_syslog(str_arg.pbuf,LOG_USER | LOG_INFO);

        if(str_equal_text(&str_cmd,"USER")) {
            handle_user(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"PASS")) {
            handle_pass(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"SYST")) {
            handle_syst();
        }
        else if(str_equal_text(&str_cmd,"QUIT")) {
            handle_quit();
        }
        else {
            write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"  Please login with USER and PASS.\n");
            str_free(&str_cmd);
            str_free(&str_arg);
        }
    }
}

struct mystr get_rpc_request(struct mystr *str_arg)
{
    int nread;
    char term = '\n';
    const char *p_src = NULL;
    struct mystr str_line = INIT_MYSTR;
    struct mystr str_cmd  =  INIT_MYSTR;
    nread = get_netdata(&str_line,term);
    if(!nread){
        sysutil_exit(-1);
        handle_quit();
    }

    if(str_get_char_at(&str_line,nread-1) == '\r') {
        str_alloc_alt_term(&str_cmd,str_line.pbuf,'\0');
        str_free(&str_line);
    }

    str_split_char(&str_cmd,str_arg,' ');
    if(str_contains_space(str_arg))
    {
        *str_arg = str_wipeout_blank(str_arg);
    }

    str_upper(&str_cmd);
    return str_cmd;

}
