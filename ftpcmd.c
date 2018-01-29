#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "ftpcmd.h"
#include "ftpcode.h"
#include "commoncode.h"
#include "dataprocess.h"

void handle_pasv(struct ftpd_session *session, struct mystr *str_arg)
{

}

void handle_user(struct ftpd_session *session, struct mystr *str_arg)
{
    if(!str_contains_unprintable(str_arg) || !str_all_space(str_arg) || str_getlen(str_arg) < 128)
    {
        if(!str_isempty(&session->user_str))
        {
            str_free(&session->user_str);
        }
        session->user_str  = *str_arg;
    }
    if(!str_isempty(&session->passwd_str))
    {
        str_free(&session->passwd_str);
    }
    write_cmd_respond(FTPD_CMDWRIO,FTP_GIVEPWORD," Please specify user password.\n");
}

void handle_pass(struct ftpd_session *session, struct mystr *str_arg)
{
    int retval;
    if(str_isempty(&session->user_str))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_NEEDUSER," Please first login with USER.\n");
        return;
    }

    if(str_equal_text(&session->user_str,"ANONYMOUS"))
    {
        str_empty(str_arg);
    }

    set_request_data(session->child_fd,str_arg,&session->user_str);

    retval = get_cmd_responds(session->child_fd);
    switch(retval)
    {
    case PUNIXSOCKLOGINFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR," Login incorrect.\n");
        session->login_fails = 1;
        break;
    case PUNIXSOCKLOGINOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINOK," Login successful.\n");
        session->login_fails = 0;
        break;
    };
    str_free(str_arg);

    sysutil_close(session->child_fd);
    session->child_fd = -1;

}

void handle_abot()
{

}

void handle_cdup()
{

}

void handle_pwd()
{

}

void handle_dele()
{

}

void handle_help()
{

}

void handle_list()
{

}

void handle_mkd()
{

}

void handle_mode()
{

}

void handle_noop()
{

}

void handle_port()
{
}

void handle_quit()
{
    write_cmd_respond(FTPD_CMDWRIO,FTP_GOODBYE," GoodBye.\n");
    sysutil_exit(0);
}

void handle_rest()
{

}

void handle_retr()
{

}
void handle_rmd()
{

}

void handle_rnfr()
{

}

void handle_stor()
{

}

void handle_stou()
{

}

void handle_appe()
{

}

void handle_syst(struct ftpd_session *session)
{
    if(!session->login_fails)
    {
        const char *p_src = NULL;
        p_src = sysutil_uname();
        write_cmd_respond(FTPD_CMDWRIO,FTP_SYSTOK,p_src);

        sysutil_free(p_src);
        sysutil_exit(0);
    }
    write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"  Please login with USER and PASS.\n");
}


