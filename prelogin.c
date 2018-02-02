#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <shadow.h>
#include "sysutil.h"
#include "prelogin.h"
#include "ftpcode.h"
#include "commoncode.h"
#include "ftpcmd.h"

void init_connection(struct ftpd_session *session)
{
    struct mystr str_cmd = INIT_MYSTR;

    while(1)
    {
        struct mystr str_arg = INIT_MYSTR;
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
            handle_syst(session);
        }
        else if(str_equal_text(&str_cmd,"QUIT")) {
            handle_quit();
        }
        else {
            write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"Please login with USER and PASS.\n");
            str_free(&str_arg);

        }
        str_free(&str_cmd);

    }
}

struct mystr get_rpc_request(struct mystr *str_arg)
{
    int nread;
    char term = '\n';
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

void user_common_deal(struct ftpd_session *session)
{
    int retval;

    set_private_unix_socket(session);
    retval = sysutil_fork();

    if(retval)
    {
        sysutil_install_null_sighandler(kVSFSysUtilSigCHLD);
        sysutil_install_null_sighandler(kVSFSysUtilSigPIPE);
        close_child_context(session);
        login_user(session);

        while(1)
        {
            common_request(session);
        }
    }

    str_free(&session->user_str);
    str_free(&session->passwd_str);

    close_parent_context(session);
    del_privilege();
    wait_data_connection(session);

}

void common_request(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    private_str_alloc_memchunk(&str_buf,NULL,FTPD_UNIXSOCK_LEN);

    while(1)
    {
        get_request_data(session->parent_fd,&str_buf);

        parse_cmd(session,&str_buf);

        if(sysutil_wait_reap_one())
            sysutil_exit(0);
    }
    str_free(&str_buf);
}


void wait_data_connection(struct ftpd_session *session)
{
    struct mystr str_cmd = INIT_MYSTR;

    while(1)
    {
        struct mystr str_arg = INIT_MYSTR;
        str_cmd = get_rpc_request(&str_arg);

        sysutil_syslog(str_cmd.pbuf,LOG_USER | LOG_INFO);
        sysutil_syslog(str_arg.pbuf,LOG_USER | LOG_INFO);

        if(str_equal_text(&str_cmd,"PWD")) {
            handle_pwd(session);
        }
        else if(str_equal_text(&str_cmd,"CWD")) {
            handle_cwd(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"PORT")) {
            handle_port(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"PASV")) {
            handle_pasv(session);
        }
        else if(str_equal_text(&str_cmd,"LIST")) {
            handle_list(session);
        }
        else if(str_equal_text(&str_cmd,"CDUP")) {
            handle_cdup(session);
        }
        else if(str_equal_text(&str_cmd,"TYPE")) {
            handle_type(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"REST")) {
            handle_rest(session);
        }
        else if(str_equal_text(&str_cmd,"RETR")) {
            handle_retr(session);
        }
        else if(str_equal_text(&str_cmd,"MKD")) {
            handle_mkd(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"QUIT")) {
            handle_quit();
        }
        else {
            write_cmd_respond(FTPD_CMDWRIO,FTP_COMMANDNOTIMPL,"Invalid command.\n");
            str_free(&str_arg);

        }
        str_free(&str_cmd);

    }
}

int prepare_login(struct mystr *str_arg,struct ftpd_session *session)
{

    sysutil_syslog("prepare login",LOG_INFO | LOG_USER);
    int ulong_size = sizeof(unsigned long);
    struct mystr str_user = INIT_MYSTR;
    struct mystr str_pass = INIT_MYSTR;

    str_split_char(str_arg,&str_user,' ');
    str_split_char(&str_user,&str_pass,' ');

    if(!str_equal_text(&str_user,"anonymous"))
    {
        struct spwd *passwd = getspnam(str_user.pbuf);
        if(!passwd)
        {
            str_free(&str_user);
            str_free(&str_pass);
            session->login_fails = 1;
            set_respond_data(session->parent_fd,PCMDRESPONDLOGINFAIL);
            return 0;
        }

        if(str_isempty(&str_pass) || str_all_space(&str_pass) || str_getlen(&str_pass) > 128
                        || str_contains_unprintable(&str_pass) || sysutil_strcmp(passwd->sp_pwdp,
                                                    (char*)crypt(str_pass.pbuf, passwd->sp_pwdp)))
        {
            str_free(&str_user);
            str_free(&str_pass);
            session->login_fails = 1;
            set_respond_data(session->parent_fd,PCMDRESPONDLOGINFAIL);
            return 0;
        }
    }
    else
    {
        str_free(&str_user);
        str_alloc_text(&str_user,"ftp");
    }


    set_respond_data(session->parent_fd,PCMDRESPONDLOGINOK);

    close_parent_context(session);

    session->user_str = str_user;
    session->passwd_str = str_pass;
    session->login_fails = 0;

    return 1;
}


void login_user(struct ftpd_session *session)
{
    struct sysutil_user *pw = sysutil_getpwnam(session->user_str.pbuf);
    if(!pw)
    {
        die("getpwname");
    }
    sysutil_chdir(pw->pw_dir);
    //sysutil_chroot(".");
    sysutil_syslog("prctl",LOG_INFO | LOG_USER);
    sysutil_prctl(PR_SET_KEEPCAPS);

    sysutil_setgid_numeric(pw->pw_gid);
    sysutil_setuid_numeric(pw->pw_uid);
    sysutil_syslog("cap_net_bind_service",LOG_INFO | LOG_USER);

    sysutil_capnetbind();
    sysutil_syslog("ok",LOG_INFO | LOG_USER);

    struct mystr str_home = INIT_MYSTR;
    str_alloc_text(&str_home,pw->pw_dir);
    session->home_str = str_home;

    struct mystr_list *p_visited_list = (struct mystr_list *)sysutil_malloc(sizeof(struct mystr_list));
    p_visited_list->pnodes = NULL;
    p_visited_list->alloc_len = p_visited_list->list_len = 0;
    str_list_add(p_visited_list,&str_home);
    session->p_visited_dir_list = p_visited_list;

}





