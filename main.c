#include <stdio.h>
#include <syslog.h>
#include "session.h"
#include "sysutil.h"
#include "ls.h"
//#include "util.h"
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

    session.idle_timeout = 20;
    session.data_timeout = 30;
    session.is_anonymous = 0;

    standalone_socket(&session);
    sysutil_openlog(LOG_DAEMON);
    twoprogress(&session);

    //util_ls("/home/usr/");


    return 0;
}
