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
        str_empty(&str_cmd);
        str_empty(&str_arg);
        str_cmd = get_cmd_from_client(&str_arg);
        sysutil_syslog(str_cmd.pbuf,LOG_USER | LOG_INFO);
        sysutil_syslog(str_arg.pbuf,LOG_USER | LOG_INFO);

        if(str_equal_text(&str_cmd,"USER")) {

            session->user_str = str_arg;
            write_cmd_respond(FTPD_CMDWRIO,FTP_GIVEPWORD," Please specify user password.\n");
        }
        else if(str_equal_text(&str_cmd,"PASS")) {
            if(str_isempty(&session->user_str))
                write_cmd_respond(FTPD_CMDWRIO,FTP_NEEDUSER," Please first login with USER.\n");
            else
                write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINOK," Login Success.\n");
        }
        else if(str_equal_text(&str_cmd,"SYST")) {
            handle_syst();
        }
        else if(str_equal_text(&str_cmd,"QUIT")) {
            handle_quit();
        }
        else {
            write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"  Please login with USER and PASS.\n");
        }
    }
}

struct mystr get_cmd_from_client(struct mystr *str_arg)
{
    int nread;
    char term = '\n';
    const char *p_src = NULL;
    struct mystr str_line = INIT_MYSTR;
    struct mystr str_cmd  =  INIT_MYSTR;

    nread = get_netdata(&str_line,term);

    if(str_get_char_at(&str_line,nread-1) == '\r')
    {
        str_alloc_alt_term(&str_cmd,str_line.pbuf,'\0');
    }

    str_split_char(&str_cmd,str_arg,' ');
    str_upper(&str_cmd);
    return str_cmd;
//    if(str_contains_unprintable(&str_line) || !str_contains_space(&str_line))
//    {
//        write_cmd_respond(FTP_CMDWRIO,FTP_LOGINERR,"BAD COMMAND!");
//    }
//    p_src = str_getbuf(&str_line);
}
