#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include "sysutil.h"
#include "dataprocess.h"
#include "commoncode.h"
#include "ftpcode.h"

int get_netdata(struct mystr *str_line,char term)
{
    struct mystr str = INIT_MYSTR;
    struct mystr line = INIT_MYSTR;
    int retval = 0;
    unsigned int term_point = 0;
    unsigned int nread = 0;

    private_str_alloc_memchunk(&str,NULL,FTPD_CMDDATA_LEN);
    while(1)
    {
        nread = message_recv_peek(FTPD_CMDRDIO,&str,FTPD_CMDDATA_LEN);
        if(!nread) {
            str_free(&str);
            return 0;
        }

        retval = str_getline(&str,&line,&term_point);
        sysutil_syslog(line.pbuf,LOG_INFO | LOG_USER);

        if(retval)
        {
            nread = read_cmd_data(FTPD_CMDRDIO,&str,term_point+1);
            sysutil_memcpy(str_line,&line,sizeof(line));

            str_free(&str);
            return term_point;
        }
        else
        {
            read_cmd_data(FTPD_CMDRDIO,&str,nread);
            str_free(&line);
            term_point = 0;
        }

    }
}

int message_recv_peek(int fd,struct mystr *p_str,unsigned int datalen)
{
    int retval;
    if((retval = sysutil_recv_peek(FTPD_CMDRDIO,p_str->pbuf,datalen)) < 0)
    {
        die("recv_peek");
    }
    p_str->alloc_bytes = retval;
    p_str->num_len = retval;
    return retval;
}

void write_cmd_respond(int fd, unsigned resp_code,const char *resp_str)
{
    struct mystr str_respond = INIT_MYSTR;
    if(resp_code > 0)
    {
        char ptr_code[4];
        snprintf(ptr_code,4,"%d",resp_code);
        str_append_text(&str_respond,ptr_code);
        str_append_char(&str_respond,' ');
    }

    str_append_text(&str_respond,resp_str);

    write_cmd_data(fd,&str_respond,str_respond.num_len);
    str_free(&str_respond);
}

void write_cmd_data(int fd,struct mystr *strbuf,unsigned int size)
{
    int nwrite;
    nwrite = sysutil_write_loop(fd,strbuf->pbuf,size);
    if(nwrite < 0)
        die("write");
}

int read_cmd_data(int fd,struct mystr *strbuf,unsigned int size)
{
    return sysutil_read_loop(fd,strbuf->pbuf,size);;
}

void get_request_data(int fd, struct mystr* str_buf)
{
    int retval;

    retval = sysutil_read(fd,str_buf->pbuf,FTPD_UNIXSOCK_LEN);
    str_buf->num_len = retval;

}

void set_request_data(int fd, struct mystr* str_buf)
{

    sysutil_syslog(str_buf->pbuf,LOG_INFO | LOG_USER);
    write_cmd_data(fd,str_buf,str_buf->num_len);
    str_free(str_buf);
}

void set_respond_data(int fd, enum PUNIXLOGINSTATUS status)
{
    struct mystr str_buf = INIT_MYSTR;
    str_append_char(&str_buf,status);
    write_cmd_data(fd,&str_buf,str_buf.num_len);
    str_free(&str_buf);
}

int get_cmd_responds(int fd)
{
    int retval;
    char *buf = (char *)sysutil_malloc(FTPD_UNIXSOCK_LEN);

    while(!(retval = sysutil_read(fd,buf,FTPD_UNIXSOCK_LEN)))
        continue;

    retval = buf[0];
    sysutil_free(buf);

    return retval;
}

void deal_parent_respond(struct ftpd_session *session)
{
    int retval;
    retval = get_cmd_responds(session->child_fd);

    switch(retval)
    {
    case PCMDRESPONDLOGINFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"Login incorrect.\n");
        session->login_fails = 1;
        break;
    case PCMDRESPONDLOGINOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINOK,"Login successful.\n");
        session->login_fails = 0;
        break;
    case PCMDRESPONDPORTOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_PORTOK,"PORT command successful. Consider using PASV.\n");
        break;
    case PCMDRESPONDPORTFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADPROT,"PORT connection failed.\n");
        break;
    case PCMDRESPONDLISTOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
        break;
    };
}

void recv_portmod_socket(struct ftpd_session *session)
{
    int recvfd = 0;
    struct sysutil_sockaddr *port_addr;

    sysutil_recvfd(session->child_fd,&recvfd);

    sysutil_syslog("recvfd",LOG_INFO | LOG_USER);
    session->data_fd = recvfd;

    //sysutil_sockaddr_alloc_ipv4(&port_addr);
    //sysutil_getsockname(recvfd,&port_addr);
    //session->p_port_sockaddr = port_addr;

     sysutil_syslog("get sockaddr",LOG_INFO | LOG_USER);
}

int prepare_port_pattern(struct mystr *str_arg,struct ftpd_session *session)
{
    int port;
    struct sysutil_sockaddr *remote = NULL;

    {
        struct mystr str_buf = INIT_MYSTR;
        struct mystr port_real = INIT_MYSTR;
        struct mystr port_imaginary = INIT_MYSTR;

        str_split_char(str_arg,&str_buf,' ');

        str_replace_char(&str_buf,',','.');

        str_split_char_reverse(&str_buf,&port_imaginary,'.');
        str_split_char_reverse(&str_buf,&port_real,'.');
        str_free(&str_buf);

        port = sysutil_atoi(port_real.pbuf) * 256 + sysutil_atoi(port_imaginary.pbuf);
        str_free(&port_real);
        str_free(&port_imaginary);

        int sockfd;
        struct sysutil_sockaddr *local = NULL;
        sockfd = sysutil_get_ipv4_sock();
        sysutil_activate_linger(sockfd);
        sysutil_activate_noblock(sockfd);

        sysutil_sockaddr_alloc_ipv4(&local);
        sysutil_sockaddr_set_any(local);
        sysutil_sockaddr_set_port(local,FTPD_DATAPORT);

        sysutil_bind(sockfd,local);

        session->data_fd = sockfd;
        sysutil_free(local);

    }

    sysutil_sockaddr_alloc_ipv4(&remote);
    sysutil_sockaddr_set_any(remote);
    sysutil_sockaddr_set_port(remote,port);

    if(sysutil_connect_timeout(session->data_fd,&remote->u.u_sockaddr,40) < 0)
    {
        sysutil_free(remote);
        set_respond_data(session->parent_fd,PCMDRESPONDPORTFAIL);
        return 0;
    }

    session->p_port_sockaddr = remote;

    set_respond_data(session->parent_fd,PCMDRESPONDPORTOK);
    //sysutil_sendfd(session->parent_fd,sockfd);

    return 1;
}

int prepare_pasv_pattern(struct ftpd_session *session)
{
    int sockfd;


    {
        int port;
        int p_real,p_imaginary;
        srand(time(NULL));

        sysutil_syslog("select port",LOG_INFO | LOG_USER);

        do {

            port = 1025 +  rand() % (65530-1024);
            p_real = port / 256;
            p_imaginary = port % 256;

        }while(sysutil_is_port_reserved(port));

        sysutil_syslog("",LOG_INFO | LOG_USER);

        struct sysutil_sockaddr *local = NULL;
        sockfd = sysutil_get_ipv4_sock();
        sysutil_activate_noblock(sockfd);

        sysutil_sockaddr_alloc_ipv4(&local);
        sysutil_sockaddr_set_any(local);
        sysutil_sockaddr_set_port(local,port);

        sysutil_bind(sockfd,local);
        sysutil_listen(sockfd,1);

        sysutil_getsockname(sockfd,&local);

        struct mystr str_buf = INIT_MYSTR;
        struct mystr port_real = INIT_MYSTR;
        struct mystr port_imaginary = INIT_MYSTR;
        char port_buf[4] = {0};

        str_alloc_text(&str_buf,"Entering Passive Mode (");
        snprintf(port_buf,4,"%d",p_real);
        str_append_text(&port_real,port_buf);

        sysutil_memclr(port_buf,4);
        snprintf(port_buf,4,"%d",p_imaginary);
        str_append_text(&port_imaginary,port_buf);

        str_append_text(&str_buf,"127.0.0.1");//sysutil_inet_ntop(local));
        str_replace_char(&str_buf,'.',',');
        str_append_char(&str_buf,',');
        str_append_str(&str_buf,&port_real);
        str_append_char(&str_buf,',');
        str_append_str(&str_buf,&port_imaginary);
        str_append_text(&str_buf,")\n");

        write_cmd_respond(FTPD_CMDWRIO,FTP_PASVOK,str_buf.pbuf);

        str_free(&str_buf);
        str_free(&port_real);
        str_free(&port_imaginary);
        sysutil_free(local);
    }

    struct sysutil_sockaddr *remote = NULL;
    socklen_t sock_len = sizeof(*remote);
    sysutil_sockaddr_alloc_ipv4(&remote);

    int client_fd;
    client_fd = sysutil_accept_timeout(sockfd,remote,0);

    session->data_fd = client_fd;
    session->pasv_listen_fd = sockfd;
    session->p_remote_addr = remote;

    //sysutil_sendfd(session->parent_fd,sockfd);

    return 1;
}

int prepare_pwd(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    char *p_cwd = NULL;
    p_cwd = sysutil_getcwd(p_cwd,0);

    str_append_char(&str_buf,'\"');
    str_append_text(&str_buf,p_cwd);
    str_append_char(&str_buf,'\"');
    str_append_text(&str_buf," is the current directory\n");

    write_cmd_respond(FTPD_CMDWRIO,FTP_CWDOK,str_buf.pbuf);

    str_free(&str_buf);

    return 1;
}


int prepare_list(struct ftpd_session *session)
{
    sysutil_syslog("list.......",LOG_INFO | LOG_USER);
    int retval = 0;

    {
        struct mystr *str_pwd = NULL;
        struct mystr_list *p_visited_dir_list = session->p_visited_dir_list;

        str_pwd = str_list_get_pstr(p_visited_dir_list,
                       str_list_get_length(p_visited_dir_list)-1);

        retval = util_ls(session->data_fd,str_pwd->pbuf);
    }

    if(retval)
        set_respond_data(session->parent_fd,PCMDRESPONDLISTOK);

    sysutil_shutdown_failok(session->data_fd);
    if(session->pasv_listen_fd)
    {
        sysutil_shutdown_failok(session->pasv_listen_fd);
        session->pasv_listen_fd = 0;
    }

    return retval;
}

int prepare_cdup(struct ftpd_session *session)
{

}

int prepare_mkd(struct mystr *str_arg,struct ftpd_session *session)
{

}


int prepare_retr(struct mystr *str_arg,struct ftpd_session *session)
{

}

int prepare_stor(struct mystr *str_arg,struct ftpd_session *session)
{

}
int prepare_rest(struct mystr *str_arg,struct ftpd_session *session)
{

}



