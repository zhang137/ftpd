#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "ftpcmd.h"
#include "ftpcode.h"
#include "dataprocess.h"

void handle_pasv()
{

}

void handle_user()
{

}

void handle_abot()
{

}

void handle_cdup()
{

}

void handle_pwd()
{

}

void handle_dele()
{

}

void handle_help()
{

}

void handle_list()
{

}

void handle_mkd()
{

}

void handle_mode()
{

}

void handle_noop()
{

}

void handle_pass()
{

}

void handle_port()
{
}

void handle_quit()
{
    write_cmd_respond(FTPD_CMDWRIO,FTP_GOODBYE," GoodBye.\n");
}

void handle_rest()
{

}

void handle_retr()
{

}
void handle_rmd()
{

}

void handle_rnfr()
{

}

void handle_stor()
{

}

void handle_stou()
{

}

void handle_appe()
{

}

void handle_syst()
{
    const char *p_src = NULL;
    p_src = sysutil_uname();
    syslog(LOG_INFO | LOG_USER,p_src);
    write_cmd_respond(FTPD_CMDWRIO,FTP_SYSTOK,p_src);
    sysutil_free(p_src);
}


