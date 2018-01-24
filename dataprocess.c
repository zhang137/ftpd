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
        sysutil_syslog(str.pbuf,LOG_INFO | LOG_USER);
        if(!nread)
            return 0;

        retval = str_getline(&str,&line,&term_point);
        sysutil_syslog(line.pbuf,LOG_INFO | LOG_USER);
        if(retval)
        {
            nread = read_cmd_data(FTPD_CMDRDIO,&str,term_point+1);
            sysutil_memcpy(str_line,&line,sizeof(line));
            return term_point;
        }
        else
        {
            read_cmd_data(FTPD_CMDRDIO,&str,nread);
            term_point = 0;
        }

    }
}

int message_recv_peek(int fd,struct mystr *p_str,unsigned int datalen)
{
    int retval;
    while((retval = sysutil_recv_peek(FTPD_CMDRDIO,p_str->pbuf,datalen)) < 0)
    {
        if(errno == EWOULDBLOCK || errno == EINTR)
            continue;
        die("recv_peek");
    }
    p_str->alloc_bytes = retval;
    p_str->num_len = retval;
    return retval;
}

void write_cmd_respond(int fd, unsigned resp_code,const char *resp_str)
{
    char ptr_code[4];
    struct mystr str_respond = INIT_MYSTR;
    snprintf(ptr_code,4,"%d",resp_code);
    str_append_text(&str_respond,ptr_code);
    str_append_text(&str_respond,resp_str);
    write_cmd_data(fd,&str_respond,str_respond.num_len);
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
    int nread;
    nread = sysutil_read_loop(fd,strbuf->pbuf,size);
    if(nread < 0)
        die("read");
    return nread;
}






