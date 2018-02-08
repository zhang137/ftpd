#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include "ftpcmd.h"
#include "ftpcode.h"
#include "commoncode.h"
#include "dataprocess.h"


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
    sysutil_syslog("login",LOG_USER | LOG_INFO);

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

    str_append_char(&str_buf,PCMDREQUESTLOGIN);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,&session->user_str);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);


    sysutil_syslog("auth login",LOG_USER | LOG_INFO);
    sysutil_syslog(str_buf.pbuf,LOG_USER | LOG_INFO);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    deal_parent_respond(session);
    if(!session->login_fails) {
        close_child_context(session);
        sysutil_exit(0);
    }

}

void handle_abor(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTABOR);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
}

void handle_cdup(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTCDUP);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}

void handle_type(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTTYPE);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}


void handle_cwd(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTCWD);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}

void handle_pwd(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTPWD);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}


void handle_dele(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTDELE);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
}

void handle_help()
{

}

void handle_list(struct ftpd_session *session)
{

    struct mystr str_buf = INIT_MYSTR;
    str_append_char(&str_buf,PCMDREQUESTLIST);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}

void handle_mkd(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTMKD);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
}

void handle_mode()
{

}

void handle_noop(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTNOOP);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
}

void handle_size(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTSIZE);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}

void handle_mdtm(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTMDTM);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

   // deal_parent_respond(session);

}

void handle_port(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTPORT);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}

void handle_pasv(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTPASV);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}

void handle_quit()
{
    write_cmd_respond(FTPD_CMDWRIO,FTP_GOODBYE,"GoodBye.\n");
    sysutil_exit(0);
}

void handle_retr(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTRETR);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);

    //deal_parent_respond(session);
}
void handle_rmd(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTRMD);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
    //deal_parent_respond(session);
}

void handle_rnfr(struct ftpd_session *session, struct mystr *str_arg)
{
    //deal_parent_respond(session);
}

void handle_stor(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTSTOR);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
}

void handle_rest(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTREST);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
    //deal_parent_respond(session);
}

void handle_stou(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTSTOU);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
}

void handle_appe(struct ftpd_session *session, struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,PCMDREQUESTAPPE);
    str_append_char(&str_buf,' ');
    str_append_str(&str_buf,str_arg);

    write_internal_cmd_request(session->child_fd,&str_buf);
    str_free(&str_buf);
}

void handle_syst(struct ftpd_session *session)
{
    //if(!session->login_fails)
    //{
    struct mystr str_respond = INIT_MYSTR;

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
        //sysutil_exit(0);
    //}
    //write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"Please login with USER and PASS.\n");
}


