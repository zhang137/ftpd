#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
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
    write_cmd_respond(FTPD_CMDWRIO,FTP_GIVEPWORD,"Please specify user password.\n");
}

void handle_pass(struct ftpd_session *session, struct mystr *str_arg)
{
    int retval;
    if(str_isempty(&session->user_str))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_NEEDUSER,"Please first login with USER.\n");
        return;
    }

    if(str_equal_text(&session->user_str,"ANONYMOUS"))
    {
        str_empty(str_arg);
    }

    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PUNIXSOCKLOGIN);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,&session->user_str);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    set_request_data(session->child_fd,&str_buf);
    str_free(str_arg);

    deal_parent_respond(session);
    if(!session->login_fails)
        close_child_context(session);

}

void handle_abot()
{

}

void handle_cdup(struct ftpd_session *session)
{

}

void handle_cwd(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PUNIXSOCKPWD);
    set_request_data(session->child_fd,&str_buf);
    str_free(&str_buf);

}

void handle_dele()
{

}

void handle_help()
{

}

void handle_list(struct ftpd_session *session)
{
    write_cmd_respond(FTPD_CMDWRIO,FTP_DATACONN,"Here comes the directory listing.\n");

    struct mystr str_buf = INIT_MYSTR;
    str_append_char(&str_buf,PUNIXSOCKLIST);
    set_request_data(session->child_fd,&str_buf);
    str_free(&str_buf);

    deal_parent_respond(session);
    //util_ls(session->data_fd,session->home_str.pbuf);

}

void handle_mkd(struct ftpd_session *session, struct mystr *str_arg)
{

}

void handle_mode()
{

}

void handle_noop()
{

}

void handle_port(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PUNIXSOCKPORT);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    set_request_data(session->child_fd,&str_buf);
    str_free(str_arg);

    deal_parent_respond(session);
    //recv_portmod_socket(session);


}

void handle_quit()
{
    write_cmd_respond(FTPD_CMDWRIO,FTP_GOODBYE,"GoodBye.\n");
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
        struct mystr str_respond = INIT_MYSTR;
        p_src = sysutil_uname();

#ifdef __linux__
        str_alloc_text(&str_respond,"UNIX Type: L");
#endif  //UNIX
#ifdef __unix__
        str_alloc_text(&str_respond,"UNIX Type: L");
#endif  //UNIX
#ifdef _WIN32
        str_alloc_text(&str_respond,"WINDOWS Type: L");
#endif // _WIN32
        char char_bit = CHAR_BIT+'0';
        str_append_char(&str_respond,char_bit);
        str_append_char(&str_respond,'\n');

        write_cmd_respond(FTPD_CMDWRIO,FTP_SYSTOK,str_respond.pbuf);

        str_free(&str_respond);
        sysutil_exit(0);
    }
    write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"Please login with USER and PASS.\n");
}


