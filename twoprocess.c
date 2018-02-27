#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include "sysutil.h"
#include "prelogin.h"
#include "twoprocess.h"
#include "dataprocess.h"
#include "ftpcode.h"
#include "commoncode.h"
#include "tunable.h"


void twoprogress(struct ftpd_session *session)
{
    int retval;
    create_private_unix_socket(session);

    retval = sysutil_fork();
    sysutil_install_null_sighandler(kVSFSysUtilSigPIPE);
    sysutil_install_null_sighandler(kVSFSysUtilSigCHLD);

    if(retval)
    {
        close_child_context(session);
        while(1)
        {
            process_login_req(session);
        }
    }

    write_cmd_respond(FTPD_CMDWRIO,FTP_GREET,"Welcome to zyy's ftpd\n");
    close_parent_context(session);
    sysutil_die_follow_parent();
    drop_all_privs();
    init_connection(session);


}

void create_private_unix_socket(struct ftpd_session *session)
{
    struct sysutil_socketpair_retval sockpair;

    sockpair = sysutil_unix_stream_socketpair();
    session->child_fd = sockpair.socket_one;
    session->parent_fd = sockpair.socket_two;
}

void close_parent_context(struct ftpd_session *session)
{
    sysutil_close(session->parent_fd);
    session->parent_fd = -1;
}

void close_child_context(struct ftpd_session *session)
{
    sysutil_close(session->child_fd);
    session->child_fd = -1;
}

void drop_all_privs()
{
    int res;
    int saved_uid,saved_gid;
    struct mystr nobody;
    struct sysutil_user *passwd = NULL;

    str_alloc_text(&nobody,tunable_nobody);
    passwd = sysutil_getpwnam(str_getbuf(&nobody));
    if(!passwd)
    {
        str_free(&nobody);
        die("getpwname");
    }
//    res = setgroups(0,NULL);
//    if(res < 0)
//    {
//        die("setgroups");
//    }

    //sysutil_syslog(passwd->pw_dir,LOG_INFO | LOG_USER);

    sysutil_chroot(".");
    sysutil_set_no_procs();
    sysutil_set_no_fds();

    saved_gid = sysutil_getuid();
    saved_uid = sysutil_getpid();

    sysutil_setgid_numeric(passwd->pw_gid);
    sysutil_setuid_numeric(passwd->pw_uid);

    //sysutil_syslog("seteuid",LOG_INFO | LOG_USER);
    //sysutil_seteuid_numeric(passwd->pw_uid);
    //sysutil_setegid_numeric(passwd->pw_gid);

}

void process_login_req(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    private_str_alloc_memchunk(&str_buf,NULL,FTPD_UNIXSOCK_LEN);

    while(1)
    {
        get_internal_cmd_data(session->parent_fd,&str_buf);
        parse_cmd(session,&str_buf);

        if(!session->login_fails)
            break;

        if(sysutil_wait_reap_one())
            sysutil_exit(0);

    }

    user_common_deal(session);
}

int parse_cmd(struct ftpd_session *session, struct mystr *p_str)
{
    int cmd;
    int retval = 0;

    if(!p_str->num_len)
        return retval;

    cmd = str_get_char_at(p_str,0);
    switch(cmd)
    {
    case PCMDREQUESTLOGIN:
        retval = prepare_login(p_str,session);
        break;
    case PCMDREQUESTPORT:
        prepare_port_pattern(p_str,session);
        break;
    case PCMDREQUESTPASV:
        prepare_pasv_pattern(session);
        break;
    case PCMDREQUESTPWD:
        prepare_pwd(session);
        break;
    case PCMDREQUESTCWD:
        prepare_cwd(p_str,session);
        break;
    case PCMDREQUESTMKD:
        prepare_mkd(p_str,session);
        break;
    case PCMDREQUESTLIST:
        prepare_list(session);
        break;
    case PCMDREQUESTTYPE:
        prepare_type(p_str,session);
        break;
    case PCMDREQUESTCDUP:
        prepare_cdup(session);
        break;
    case PCMDREQUESTREST:
        prepare_rest(p_str,session);
        break;
    case PCMDREQUESTRETR:
        prepare_retr(p_str,session);
        break;
    case PCMDREQUESTSTOR:
        prepare_stor(p_str,session);
        break;
    case PCMDREQUESTSTOU:
        prepare_stou(p_str,session);
        break;
    case PCMDREQUESTAPPE:
        prepare_appe(p_str,session);
        break;
    case PCMDREQUESTRMD:
        prepare_rmd(p_str,session);
        break;
    case PCMDREQUESTDELE:
        prepare_dele(p_str,session);
        break;
    case PCMDREQUESTSIZE:
        prepare_size(p_str,session);
        break;
    case PCMDREQUESTMDTM:
        prepare_mdtm(p_str,session);
        break;
    case PCMDREQUESTNOOP:
        prepare_noop(session);
        break;
    case PCMDREQUESTABOR:
        prepare_abor(session);
        break;
    }

    str_empty(p_str);

    return retval;
}










