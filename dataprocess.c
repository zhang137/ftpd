#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "dataprocess.h"
#include "sysutil.h"
#include "commoncode.h"
#include "ftpcode.h"


int get_netdata(struct mystr *str_arg,int *end_point,char term)
{
    struct mystr str_line = INIT_MYSTR;
    unsigned int term_point = 0;
    unsigned int nread = 0,i;

    private_str_alloc_memchunk(&str_line,NULL,FTPD_CMDDATA_LEN);

    while(1)
    {
        nread = sysutil_recv_peek(FTP_CMDRDIO,str_line.pbuf,FTPD_CMDDATA_LEN);
        if(sysutil_retval_is_error(nread))
        {
            if(errno == EWOULDBLOCK || errno == EINTR)
                continue;
            die("recv");
        }
        if(!nread)
            return 0;
        for (i = 0; i < nread; i++)
        {
            if(str_get_char_at(str_line.pbuf,i) == term)
                term_point = i;
        }
        if(term_point != nread)
        {
            nread = read_cmd_data(FTP_CMDRDIO,&str_line,term_point);
            *end_point = term_point;
            sysutil_memcpy(str_arg,&str_line,szieof(str_line));
            return nread;
        }
        else
        {
            read_cmd_data(FTP_CMDRDIO,&str_line,nread);
            term_point = 0;
        }

    }
}

int write_cmd_respond(int fd, unsigned resp_code,const char *resp_str)
{
    struct mystr str_respond = INIT_MYSTR;
    str_alloc_ulong(&str_respond,resp_code);
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






