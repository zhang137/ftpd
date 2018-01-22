#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include "twoprocess.h"
#include "prelogin.h"

void twoprogress(struct ftpd_session *session)
{
    int client_fd;
    set_private_unix_socket(session);

    //session->

}

void set_private_unix_socket(struct ftpd_session *session)
{
    struct sysutil_socketpair_retval sockpair;

    sockpair = sysutil_unix_stream_socketpair();
    session->child_fd = sockpair.socket_one;
    session->parent_fd = sockpair.socket_two;
}

