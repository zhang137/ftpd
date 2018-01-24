#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include "sysutil.h"
#include "dataprocess.h"
#include "commoncode.h"
#include "ftpcode.h"

int get_netdata(struct mystr *str_arg,char term)
{
    struct mystr str_line = INIT_MYSTR;
    unsigned int term_point = 0;
    unsigned int nread = 0,i;

    private_str_alloc_memchunk(&str_line,NULL,FTPD_CMDDATA_LEN);
    while(1)
    {
        nread = sysutil_recv_peek(FTPD_CMDRDIO,str_line.pbuf,FTPD_CMDDATA_LEN);

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
            if(str_get_char_at(&str_line,i) == term)
                term_point = i;
        }

        if(term_point != nread)
        {
            nread = read_cmd_data(FTPD_CMDRDIO,&str_line,term_point+1);
            sysutil_memcpy(str_arg,&str_line,sizeof(str_line));
            return term_point;
        }
        else
        {
            read_cmd_data(FTPD_CMDRDIO,&str_line,nread);
            term_point = 0;
        }

    }
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






