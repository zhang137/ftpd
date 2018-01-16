#include "prelogin.h"
#include "sysutil.h"

void initialize_ftpd_socket(struct ftpd_session *session)
{
    int listen_fd;
    struct sysutil_sockaddr *listen_addr;

    sysutil_sockaddr_alloc_ipv4(&listen_addr);

    listen_fd = sysutil_get_ipv4_sock();

    sysutil_activate_noblock(listen_fd);
    sysutil_set_nodelay(listen_fd);
    sysutil_activate_reuseaddr(listen_fd);
    sysutil_set_iptos_throughput(listen_fd);
    sysutil_activate_keepalive(listen_fd);
    sysutil_activate_oobinline(listen_fd);
    sysutil_activate_linger(listen_fd);

    sysutil_bind(listen_fd,listen_addr);

    sysutil_listen(listen_fd,SOMAXCONN);

    session->p_local_addr = listen_addr;

    while(1)
    {

        struct sysutil_sockaddr client_addr;
        int client_fd,addr_len = sizeof(client_addr);

        client_fd = sysutil_accept_timeout(listen_fd,&client_addr,session->accept_timeout);
        if(client_fd < 0 )
        {
           if(!saved_errno)
                continue;
            else
            {

            }
        }



    }


}



