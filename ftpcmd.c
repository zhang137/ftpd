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
    if(!str_contains_unprintable(str_arg) || !str_all_space(str_arg))
        session->user_str = *str_arg;

    if(str_equal_text(str_arg,"ANONYMOUS"))
    {

    }
    write_cmd_respond(FTPD_CMDWRIO,FTP_GIVEPWORD," Please specify user password.\n");
}

void handle_pass(struct ftpd_session *session, struct mystr *str_arg)
{
    int retval;
    struct mystr strbuf = INIT_MYSTR;

    if(str_isempty(&(session->user_str)))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_NEEDUSER," Please first login with USER.\n");
        return;
    }
    if(!str_all_space(str_arg) || !str_contains_unprintable(str_arg))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR," The password contains illegal characters or is null.\n");
        return;
    }

    if(str_getlen(&str_arg) > 128)
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR," The password is too long");
        return ;
    }

    retval = get_cmd_responds(session->child_fd);
    switch(retval)
    {
    case PUNIXSOCKLOGINFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINOK," Login incorrect.\n");
        break;
    case PUNIXSOCKLOGINOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINOK," Login successful.\n");
        sysutil_exit(0);
    };
        // todo
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

void handle_syst()
{
    const char *p_src = NULL;
    p_src = sysutil_uname();
    syslog(LOG_INFO | LOG_USER,p_src);
    write_cmd_respond(FTPD_CMDWRIO,FTP_SYSTOK,p_src);
    sysutil_free(p_src);
}


