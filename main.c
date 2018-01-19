#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "session.h"
#include "twoprocess.h"
#include "sysutil.h"
#include "twoprocess.h"


int main()
{
    struct ftpd_session session = {
        NULL, NULL, NULL, 0, 0, 0, 0, 0,
        NULL, 0, 0, 0, 0, 0, 0, INIT_MYSTR,
        INIT_MYSTR, 0, NULL, 0, INIT_MYSTR,
        INIT_MYSTR, INIT_MYSTR, 0, 0, 0, 0,
        INIT_MYSTR, INIT_MYSTR, 0, 0, 0, 0,
        INIT_MYSTR, 0
    };

    session.accept_timeout = 20;
    session.connect_timeout = 30;
    session.idle_timeout = 20;
    session.data_timeout = 30;
    session.is_anonymous = 0;

    sysutil_deamon();

    sysutil_openlog(LOG_DAEMON);

    twoprogress(&session);

    return 0;
}
