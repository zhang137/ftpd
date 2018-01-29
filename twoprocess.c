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

extern const char* const tunable_nobody;


void twoprogress(struct ftpd_session *session)
{
    int retval;
    set_private_unix_socket(session);

    write_cmd_respond(FTPD_CMDWRIO,FTP_GREET," Welcome to zyy's ftpd\n");
    retval = sysutil_fork();

    if(retval)
    {
        sysutil_install_null_sighandler(kVSFSysUtilSigCHLD);
        sysutil_install_null_sighandler(kVSFSysUtilSigPIPE);
        close_child_context(session);
        while(1)
        {
            sysutil_syslog("parent wait",LOG_INFO | LOG_USER);
            deal_private_req(session);
        }
    }
    close_parent_context(session);
    del_privilege();
    init_connection(session);
    //

}

void set_private_unix_socket(struct ftpd_session *session)
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
    sysutil_activate_noblock(session->child_fd);
}

void close_child_context(struct ftpd_session *session)
{
    sysutil_close(session->child_fd);
    session->child_fd = -1;
    sysutil_activate_noblock(session->parent_fd);
}

void del_privilege()
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

    saved_gid = sysutil_getuid();
    saved_uid = sysutil_getpid();

    sysutil_seteuid_numeric(passwd->pw_uid);
    sysutil_setegid_numeric(passwd->pw_gid);

    sysutil_chdir(passwd->pw_dir);

    sysutil_chroot(".");
}

void deal_private_req(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    while(1)
    {
        private_str_alloc_memchunk(&str_buf,NULL,FTPD_UNIXSOCK_LEN);
        get_request_data(session->parent_fd,&str_buf);

        if(parse_cmd(session,&str_buf))
            break;

        if(sysutil_wait_reap_one())
            sysutil_exit(0);
    }

    ready_to_login(session);
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
    case PUNIXSOCKLOGIN:
        retval = prepare_login(p_str,session);
        break;
    case PUNIXSOCKPWD:
        break;
    }

    return retval;
}










