#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
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
    case PUNIXSOCKLOGINFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINERR,"Login incorrect.\n");
        session->login_fails = 1;
        break;
    case PUNIXSOCKLOGINOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_LOGINOK,"Login successful.\n");
        session->login_fails = 0;
        break;
    case PUNIXSOCKPORTOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_PORTOK,"PORT command successful. Consider using PASV.\n");
        break;
    case PUNIXSOCKPORTFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADPROT,"PORT connection failed.\n");
        break;
    case PUNIXSOCKLISTOK:
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






