#include "util.h"
#include "sysutil.h"

void standalone_socket(struct ftpd_session *session)
{
    int fd,retval;
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

    struct sysutil_sockaddr *listen_addr;
    struct sysutil_sockaddr *client_addr;

    fd = sysutil_get_ipv4_sock();
    sysutil_activate_reuseaddr(fd);
    sysutil_sockaddr_alloc_ipv4(&listen_addr);
    sysutil_sockaddr_set_any(listen_addr);
    sysutil_sockaddr_set_port(listen_addr,21);

    if(sysutil_bind(fd,listen_addr)  < 0)
        die("bind");

    if(sysutil_listen(fd,SOMAXCONN)  < 0)
        die("listen");

    sysutil_sockaddr_alloc_ipv4(client_addr);
    int client_fd;
    int addr_len = sizeof(*client_addr);

    while(1)
    {
        retval = sysutil_accept_timeout(fd,client_addr,0);
        if(sysutil_retval_is_error(retval))
        {
            continue;
        }

        sysutil_activate_noblock(retval);
        sysutil_set_sockopt(retval);

        session->p_local_addr = listen_addr;
        session->p_remote_addr = client_addr;


        if(!sysutil_fork_failok())
        {
            sysutil_close(retval);
            break;
        }
        sysutil_close(retval);
    }
    util_client_dup2(retval);
}

void util_client_dup2(int fd)
{
    sysutil_dupfd2(STDIN_FILENO,fd);
    sysutil_dupfd2(STDOUT_FILENO,fd);
    sysutil_dupfd2(STDERR_FILENO,fd);

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




