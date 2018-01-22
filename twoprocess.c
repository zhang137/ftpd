#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include "twoprocess.h"
#include "prelogin.h"

void twoprogress(struct ftpd_session *session)
{
    int retval;
    set_private_unix_socket(session);

    retval = sysutil_fork();
    if(!retval)
    {
        util_close_child_context(session);

    }
    util_close_parent_context(session);


    //session->

}

void set_private_unix_socket(struct ftpd_session *session)
{
    struct sysutil_socketpair_retval sockpair;

    sockpair = sysutil_unix_stream_socketpair();
    session->child_fd = sockpair.socket_one;
    session->parent_fd = sockpair.socket_two;
}

void util_close_parent_context(struct ftpd_session *session)
{
    sysutil_close(session->parent_fd);
    session->parent_fd = -1;
}

void util_close_child_context(struct ftpd_session *session)
{
    sysutil_close(session->child_fd);
    session->child_fd = -1;
}

void delall_privilege()
{
    int res;
    int seved_uid,saved_gid;
    struct mystr nobody = INIT_MYSTR;
    struct sysutil_user *passwd = NULL;

    str_alloc_text(nobody,trunable_nobody);
    passwd = sysutil_getpwnam(mystr->pbuf);
    if(!passwd)
    {
        str_free(&nobody);
        die("getpwname");
    }

    res = setgroups(0,NULL);
    if(res < 0)
    {
        die("setgroups");
    }

    saved_gid = sysutil_getuid();
    saved_uid = sysutil_getpid();

    sysutil_seteuid_numeric(passwd->pw_uid);
    sysutil_setegid_numeric(passwd->pw_gid);

    sysutil_chdir(passwd->pw_dir);

    sysutil_chroot(".");
}











