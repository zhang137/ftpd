#include <stdio.h>
#include <syslog.h>
#include "sysutil.h"
#include "util.h"
#include "commoncode.h"

void standalone_socket(struct ftpd_session *session)
{
    int listen_fd,client_fd;
    if(sysutil_fork() > 0)
    {
        sysutil_exit(0);
    }

    if(setsid() < 0)
    {
        die("setsid");
    }

    if(sysutil_fork() > 0)
    {
        sysutil_exit(0);
    }

    sysutil_clear_fd();
    sysutil_chdir("/");
    sysutil_set_umask(0);

    struct sysutil_sockaddr *listen_addr = NULL;
    struct sysutil_sockaddr *client_addr = NULL;

    listen_fd = sysutil_get_ipv4_sock();
    sysutil_activate_reuseaddr(listen_fd);

    sysutil_sockaddr_alloc_ipv4(&listen_addr);
    sysutil_sockaddr_set_any(listen_addr);
    sysutil_sockaddr_set_port(listen_addr,FTPD_CMDPORT);

    if(sysutil_bind(listen_fd,listen_addr))
        die("Port used");

    sysutil_sockaddr_clear(&listen_addr);

    if(sysutil_listen(listen_fd,SOMAXCONN))
        die("listen");

    sysutil_sockaddr_alloc_ipv4(&client_addr);

    sysutil_install_null_sighandler(kVSFSysUtilSigCHLD);

    while(1)
    {
        client_fd = sysutil_accept_timeout(listen_fd,client_addr,0);
        if(sysutil_retval_is_error(client_fd))
        {
            continue;
        }
        sysutil_activate_noblock(client_fd);
        sysutil_set_sockopt(client_fd);

        sysutil_sockaddr_alloc_ipv4(&listen_addr);
        sysutil_getsockname(client_fd,&listen_addr);

        session->p_local_addr = listen_addr;
        session->p_remote_addr = client_addr;

        if(!sysutil_fork_failok())
        {
            sysutil_close(listen_fd);
            util_client_dup2(client_fd);
            return;
        }
        sysutil_close(client_fd);
    }

}

void util_client_dup2(int fd)
{
    sysutil_dupfd2(fd,0);
    sysutil_dupfd2(fd,1);
    sysutil_dupfd2(fd,2);

    if(fd > 2)
    {
        sysutil_close(fd);
    }
}

void init_session()
{

}

void load_default_config()
{

}









