#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "session.h"
#include "twoprocess.h"
#include "sysutil.h"
#include "prelogin.h"
#include "str.h"
#include "strlist.h"
#include <fcntl.h>


int main()
{
    pid_t pid;
    int fd,fd2;
    char str[10] = "";
    struct ftpd_session session;
    session.accept_timeout = 20;
    session.connect_timeout = 30;
    session.idle_timeout = 20;
    session.data_timeout = 30;
    session.is_anonymous = 0;

    sysutil_deamon();
    initialize_ftpd_socket(&session);

    return 0;
}
