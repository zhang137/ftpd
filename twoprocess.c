#include "twoprocess.h"


void twoprogress(struct ftpd_session *session)
{
    int client_fd;
    struct sysutil_socketpair_retval sockpair;
    client_fd = wait_client_connect(session);

    sockpair = sysutil_unix_stream_socketpair();
    session->child_fd = sockpair->socket_two;
    session->parent_fd = sockpair->socket_one;



}

void set_ftp_sockopt(int fd)
{
    sysutil_set_nodelay(fd);
    sysutil_activate_reuseaddr(fd);
    sysutil_activate_keepalive(fd);
    sysutil_activate_oobinline(fd);
    sysutil_activate_linger(fd);
}

int initialize_ftpd_socket(struct sysutil_sockaddr *listen_addr)
{
    int listen_fd;

    listen_fd = sysutil_get_ipv4_sock();

    set_ftp_sockopt(listen_fd);
    sysutil_sockaddr_alloc_ipv4(&listen_addr);
    sysutil_sockaddr_set_any(&listen_addr);
    sysutil_sockaddr_set_port(&listen_addr,20);

    sysutil_bind(listen_fd,listen_addr);
    sysutil_listen(listen_fd,SOMAXCONN);

    return listen_fd;
}

int wait_client_connect(struct session *session)
{

    int listen_fd,client_fd;
    int addr_len = sizeof(client_addr);
    struct sysutil_sockaddr *listen_addr;
    struct sysutil_sockaddr client_addr;

    listen_fd = initialize_ftpd_socket(listen_addr);

    while(1)
    {
        client_fd = sysutil_accept_timeout(listen_fd,&client_addr,session->accept_timeout);
        if(client_fd < 0 )
        {
           if(saved_errno == EWOULDBLOCK || saved_errno == EINTR)
                continue;
            else
            {
                ;//die("accept");
            }
        }

        sysutil_activate_noblock(client_fd);
        session->p_local_addr = listen_addr;
        session->p_remote_addr = client_addr;

        if(!sysutil_fork_failok())
        {
            sysutil_close(listen_fd);
            break;
        }
        sysutil_close(client_fd);
    }
    return client_fd;
}




