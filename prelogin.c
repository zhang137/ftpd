#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
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
            write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"  Please login with USER and PASS.\n");
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

int prepare_login(struct mystr *str_arg,struct ftpd_session *session)
{

    sysutil_syslog("prepare login",LOG_INFO | LOG_USER);
    int ulong_size = sizeof(unsigned long);
    struct mystr str_user = INIT_MYSTR;
    struct mystr str_pass = INIT_MYSTR;

    str_split_char(str_arg,&str_user,' ');
    str_free(str_arg);
    str_split_char(&str_user,&str_pass,' ');

    if(!str_equal_text(&str_user,"ANONYMOUS"))
    {
        struct spwd *passwd = getspnam(str_user.pbuf);
        if(!passwd)
        {
            sysutil_syslog("getpwnam error",LOG_INFO | LOG_USER);
            str_free(&str_user);
            str_free(&str_pass);
            set_respond_data(session->parent_fd,PUNIXSOCKLOGINFAIL);
            return 0;
        }

        if(str_all_space(&str_pass) || str_getlen(&str_pass) > 128 || str_contains_unprintable(&str_pass)
               || sysutil_strcmp(passwd->sp_pwdp, (char*)crypt(str_pass.pbuf, passwd->sp_pwdp)))
        {
            str_free(&str_user);
            str_free(&str_pass);
            set_respond_data(session->parent_fd,PUNIXSOCKLOGINFAIL);
            return 0;
        }
    }
    else
    {
        str_free(&str_user);
        str_alloc_text(&str_user,"ftp");
    }


    set_respond_data(session->parent_fd,PUNIXSOCKLOGINOK);

    sysutil_close(session->parent_fd);
    session->parent_fd = -1;

    session->user_str = str_user;
    session->passwd_str = str_pass;

    return 1;
}

void ready_to_login(struct ftpd_session *session)
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
            ;
        }
    }

    str_free(&session->user_str);
    str_free(&session->passwd_str);
    close_parent_context(session);
    del_privilege();
    while(1) ;
}


void wait_data_connection()
{

}

void login_user(struct ftpd_session *session)
{

    struct sysutil_user *pw = sysutil_getpwnam(session->user_str.pbuf);
    if(!pw)
    {
        die("getpwname");
    }
    sysutil_seteuid_numeric(pw->pw_uid);
    sysutil_setegid_numeric(pw->pw_gid);
    sysutil_chdir(pw->pw_dir);

    struct mystr str_home = INIT_MYSTR;
    str_alloc_text(&str_home,pw->pw_dir);
    session->home_str = str_home;

    sysutil_chroot(".");

}





