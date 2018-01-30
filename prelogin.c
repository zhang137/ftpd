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

    close_parent_context(session);

    session->user_str = str_user;
    session->passwd_str = str_pass;

    return 1;
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

        if(parse_cmd(session,&str_buf))
            break;

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
            handle_cwd(session);
        }
        else if(str_equal_text(&str_cmd,"PORT")) {
            handle_port(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"LIST")) {
            handle_list(session);
        }
        else if(str_equal_text(&str_cmd,"MKD")) {
            handle_mkd(session,&str_arg);
        }
        else if(str_equal_text(&str_cmd,"QUIT")) {
            handle_quit();
        }
        else {
            write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"Invalid command.\n");
            str_free(&str_arg);

        }
        str_free(&str_cmd);

    }
}


int prepare_port_pattern(struct mystr *str_arg,struct ftpd_session *session)
{
    int port,sockfd;
    struct sysutil_sockaddr *remote = NULL;

    {
        struct mystr str_buf = INIT_MYSTR;
        struct mystr port_real = INIT_MYSTR;
        struct mystr port_imaginary = INIT_MYSTR;

        str_split_char(str_arg,&str_buf,' ');

        str_replace_char(&str_buf,',','.');
        sysutil_syslog(str_buf.pbuf,LOG_USER | LOG_INFO);


        str_split_char_reverse(&str_buf,&port_imaginary,'.');
        str_split_char_reverse(&str_buf,&port_real,'.');
        str_free(&str_buf);

        sysutil_syslog(port_real.pbuf,LOG_USER | LOG_INFO);
        sysutil_syslog(port_imaginary.pbuf,LOG_USER | LOG_INFO);

        port = sysutil_atoi(port_real.pbuf) * 256 + sysutil_atoi(port_imaginary.pbuf);
        str_free(&port_real);
        str_free(&port_imaginary);

    }

    sockfd = sysutil_get_ipv4_sock();
    sysutil_sockaddr_alloc_ipv4(&remote);
    sysutil_sockaddr_set_any(remote);
    sysutil_sockaddr_set_port(remote,port);

    if(sysutil_connect_timeout(sockfd,&remote->u.u_sockaddr,0) < 0)
    {
        sysutil_close(sockfd);
        sysutil_free(remote);
        set_respond_data(session->parent_fd,PUNIXSOCKPORTFAIL);
        return 0;
    }
    session->data_fd = sockfd;
    session->p_port_sockaddr = remote;
    set_respond_data(session->parent_fd,PUNIXSOCKPORTOK);

    return 1;
}

int prepare_pasv_pattern(struct mystr *str_arg,struct ftpd_session *session)
{

}

void login_user(struct ftpd_session *session)
{

    struct sysutil_user *pw = sysutil_getpwnam(session->user_str.pbuf);
    if(!pw)
    {
        die("getpwname");
    }
    sysutil_chdir(pw->pw_dir);
    sysutil_chroot(".");

    sysutil_setegid_numeric(pw->pw_gid);
    sysutil_seteuid_numeric(pw->pw_uid);

    struct mystr str_home = INIT_MYSTR;
    str_alloc_text(&str_home,pw->pw_dir);
    session->home_str = str_home;

}





