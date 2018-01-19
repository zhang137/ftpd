#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include "twoprocess.h"
#include "sysutil.h"
#include "prelogin.h"



void twoprogress(struct ftpd_session *session)
{
    int client_fd;
    struct sysutil_socketpair_retval sockpair;
    client_fd = wait_client_connect(session);

    sockpair = sysutil_unix_stream_socketpair();
    session->child_fd = sockpair.socket_one;
    session->parent_fd = sockpair.socket_two;

    sysutil_setuid_numeric(0);

    handle_prelogin(session);
    //session->

}

void set_ftp_sockopt(int fd)
{
    sysutil_set_nodelay(fd);
    sysutil_activate_keepalive(fd);
    sysutil_activate_oobinline(fd);
    sysutil_activate_linger(fd);
}

int initialize_ftpd_socket(struct sysutil_sockaddr *listen_addr)
{
    int listen_fd;
    char str[100];
    listen_fd = sysutil_get_ipv4_sock();

    sysutil_activate_reuseaddr(listen_fd);
    sysutil_sockaddr_alloc_ipv4(&listen_addr);
    sysutil_sockaddr_set_any(listen_addr);
    sysutil_sockaddr_set_port(listen_addr,21);

    if(sysutil_bind(listen_fd,listen_addr)  < 0)
        sysutil_exit(EXIT_FAILURE);

    if(sysutil_listen(listen_fd,SOMAXCONN)  < 0)
        sysutil_exit(EXIT_FAILURE);
    return listen_fd;
}

int wait_client_connect(struct ftpd_session *session)
{

    int listen_fd,client_fd;
    struct sysutil_sockaddr *listen_addr;
    struct sysutil_sockaddr client_addr;
    int addr_len = sizeof(client_addr);

    listen_fd = initialize_ftpd_socket(listen_addr);
    sysutil_syslog("start accept",LOG_INFO | LOG_USER);
    while(1)
    {
        client_fd = sysutil_accept_timeout(listen_fd,&client_addr,session->accept_timeout);
        if(client_fd <= 0 )
        {
           if(!client_fd || saved_errno & EWOULDBLOCK || saved_errno & EINTR)
                continue;
            else
            {
                sysutil_syslog("accept",LOG_ERR | LOG_USER);
                sysutil_exit(EXIT_FAILURE);
                ;//die("accept");
            }
        }

        sysutil_activate_noblock(client_fd);
        set_ftp_sockopt(client_fd);

        session->p_local_addr = listen_addr;
        session->p_remote_addr = &client_addr;

        if(!sysutil_fork_failok())
        {
            sysutil_close(listen_fd);
            break;
        }
        sysutil_close(client_fd);
    }
    return client_fd;
}




