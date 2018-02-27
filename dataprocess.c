#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <string.h>
#include <sys/sendfile.h>
#include "sysutil.h"
#include "dataprocess.h"
#include "commoncode.h"
#include "ftpcode.h"

int get_netdata(struct mystr *str_line,char term)
{
    struct mystr str_buf = INIT_MYSTR;
    struct mystr line = INIT_MYSTR;
    int retval = 0;
    unsigned int term_point = 0;
    unsigned int nread = 0;

    private_str_alloc_memchunk(&str_buf,NULL,FTPD_CMDDATA_LEN);
    while(1)
    {
        nread = message_recv_peek(FTPD_CMDRDIO,&str_buf,FTPD_CMDDATA_LEN);
        if(!nread) {
            str_free(&str_buf);
            return 0;
        }

        retval = str_getline(&str_buf,&line,&term_point);
        sysutil_syslog(line.pbuf,LOG_INFO | LOG_USER);

        if(retval)
        {
            nread = read_data(FTPD_CMDRDIO,&str_buf,term_point+1);
            sysutil_memcpy(str_line,&line,sizeof(line));

            str_free(&str_buf);
            return term_point;
        }
        else
        {
            read_data(FTPD_CMDRDIO,&str_buf,nread);
            str_empty(&str_buf);
            str_free(&line);
            term_point = 0;
        }

    }
}

int message_recv_peek(int fd,struct mystr *p_str,unsigned int datalen)
{
    int retval;
    while((retval = sysutil_recv_peek(FTPD_CMDRDIO,p_str->pbuf,datalen)) <= 0)
    {
        if(errno == EWOULDBLOCK || errno == EINTR)
            continue;
        return 0;
    }
    p_str->alloc_bytes = retval;
    p_str->num_len = retval;
    return retval;
}

void write_cmd_respond(int fd, unsigned resp_code,const char *resp_str)
{
    struct mystr str_respond = INIT_MYSTR;

    char ptr_code[4];
    snprintf(ptr_code,4,"%d",resp_code);
    str_append_text(&str_respond,ptr_code);
    str_append_char(&str_respond,' ');
    str_append_text(&str_respond,resp_str);

    write_data(fd,&str_respond,str_respond.num_len);

    str_free(&str_respond);
}

void write_remote_transfer_data(int fd, int data_mode,const char *resp_str)
{
    struct mystr str_respond = INIT_MYSTR;
    str_append_text(&str_respond,resp_str);

    if(data_mode)
    {
        struct mystr str_buf = INIT_MYSTR;
        str_right(&str_respond,&str_buf,2);
        str_append_text(&str_respond,"\r\n");
        str_free(&str_buf);
    }

    write_data(fd,&str_respond,str_respond.num_len);
    str_free(&str_respond);
}

void write_local_transfer_data(int fd, int data_mode,const char *resp_str)
{
    struct mystr str_respond = INIT_MYSTR;
    str_alloc_text(&str_respond,resp_str);

//    if(data_mode)
//    {
//        char term_char;
//        if((term_char = str_get_char_at(&str_respond,str_respond.num_len - 2)) == '\r')
//        {
//            str_replace_char_index(&str_respond,str_respond.num_len - 2,'\n');
//            str_replace_char_index(&str_respond,str_respond.num_len - 1,'\0');
//        }
//
//    }
    write_data(fd,&str_respond,str_respond.num_len);
    str_free(&str_respond);
}

void data_rate_limit_internal(int fd,int count_sum)
{
    if(!count_sum)
        return;

    unsigned int rtt = 0;
    int data_time_sum = 0;
    double utime_interval = 0.0;

    if(!(rtt = sysutil_gettcprtt(fd)))
    {
        return;
    }
    if((data_time_sum = (1000000 - (rtt * count_sum))) < 0)
    {
        return;
    }

    utime_interval = data_time_sum * 1.0 / count_sum * 1.10099;
    usleep(utime_interval);
}


int write_file_data(struct ftpd_session *session, int sendfd)
{
    int send_buf_size = FTPD_DATA_LEN;
    filesize_t total_size = session->transfer_size,already_send = 0,send_size = 0;
    int data_rate = session->bw_rate_max * 1024;
    unsigned int count_sum = 0;

    if(total_size < send_buf_size)
        send_buf_size = total_size;

    count_sum = data_rate / FTPD_DATA_LEN;

    session->bw_send_start_sec = sysutil_get_time_sec();
    session->bw_send_start_usec = sysutil_get_time_usec();

    sysutil_syslog("file sending .....",LOG_USER | LOG_INFO);
    while(already_send < total_size)
    {
        send_size = sendfile64(session->data_fd,sendfd,&session->restart_pos,send_buf_size);
        if(send_size < 0)
        {
            if(errno == EINTR)
                continue;

            char *str_error = strerror(errno);
            sysutil_syslog(str_error,LOG_USER | LOG_INFO);
            sysutil_close(sendfd);

            return -1;
        }

        already_send += send_size;

        if(session->abor_received)
        {
            session->abor_received = 0;
            sysutil_close(sendfd);
            return 0;
        }

        data_rate_limit_internal(session->data_fd,count_sum);

    }
    session->restart_pos = 0;
    sysutil_close(sendfd);
    return 1;
}


int read_file_data(struct ftpd_session *session, int fd,int mode)
{
    int recv_buf_size = FTPD_DATA_LEN;
    filesize_t already_received = 0,recv_size = 0;

    sysutil_syslog("file receiving .....",LOG_USER | LOG_INFO);
    struct mystr str_buf = INIT_MYSTR;
    private_str_alloc_memchunk(&str_buf,NULL,recv_buf_size);

    while(1)
    {
        str_empty(&str_buf);
        recv_size = sysutil_read(session->data_fd,str_buf.pbuf,recv_buf_size);
        if(recv_size <= 0)
        {
            if(!recv_size)
            {
                break;
            }

            str_free(&str_buf);
            char *error_str = strerror(errno);
            sysutil_syslog(error_str,LOG_USER | LOG_INFO);
            sysutil_close(fd);

            return -1;
        }
        sysutil_write_loop(fd,str_buf.pbuf,recv_size);
        //sysutil_write_loop(fd,str_buf.pbuf,recv_size);

        if(session->abor_received)
        {
            session->abor_received = 0;
            sysutil_close(fd);
            str_free(&str_buf);
            return 0;
        }
//        if(send_size <= total_size)
//        {
//            already_sended += send_size;
//            session->data_progress =  already_sended * 100 / total_size;
//
//            {
//                struct mystr str_respond = INIT_MYSTR;
//                char ptr_code[4];
//                snprintf(ptr_code,4,"%d",session->data_progress);
//                str_append_text(&str_respond,"data process: ");
//                str_append_text(&str_respond,ptr_code);
//                sysutil_syslog(ptr_code,LOG_USER | LOG_INFO);
//            }
//        }
    }

    str_free(&str_buf);
    session->restart_pos = 0;
    sysutil_close(fd);

    return 1;
}



void write_data(int fd,struct mystr *strbuf,unsigned int size)
{
    int nwrite;
    nwrite = sysutil_write_loop(fd,strbuf->pbuf,size);
    if(nwrite < 0)
        die("write");
}

int read_data(int fd,struct mystr *strbuf,unsigned int size)
{
    return sysutil_read_loop(fd,strbuf->pbuf,size);
}

void get_internal_cmd_data(int fd, struct mystr* str_line)
{
    int nread = 0;
    nread = sysutil_read(fd,str_line->pbuf,FTPD_UNIXSOCK_LEN);
    str_line->num_len = nread;
}

void write_internal_cmd_request(int fd, struct mystr* str_buf)
{
    sysutil_syslog(str_buf->pbuf,LOG_INFO | LOG_USER);
    write_data(fd,str_buf,str_buf->num_len);
}

void write_internal_cmd_respond(int fd, enum PUNIXCMDSTATUS status,struct mystr *str_arg)
{
    struct mystr str_buf = INIT_MYSTR;
    str_append_char(&str_buf,status);

    if(str_arg != NULL)
    {
        str_append_char(&str_buf,' ');
        str_append_str(&str_buf,str_arg);
    }

    sysutil_syslog("write internel respond",LOG_USER | LOG_INFO);
    sysutil_syslog(str_buf.pbuf,LOG_USER | LOG_INFO);

    write_data(fd,&str_buf,str_buf.num_len);
    str_free(&str_buf);
}

void recv_portmod_socket(struct ftpd_session *session)
{
    int recvfd = 0;
    //struct sysutil_sockaddr *port_addr;

    sysutil_recvfd(session->child_fd,&recvfd);
    session->data_fd = recvfd;

    //sysutil_sockaddr_alloc_ipv4(&port_addr);
    //sysutil_getsockname(recvfd,&port_addr);
    //session->p_port_sockaddr = port_addr;

     sysutil_syslog("get sockaddr",LOG_INFO | LOG_USER);
}

void clear_data_connection(struct ftpd_session *session)
{
    sysutil_shutdown_failok(session->data_fd);
    session->data_fd = -1;
    if(session->is_pasv)
    {
        sysutil_close(session->pasv_listen_fd);
        session->pasv_listen_fd = -1;
        sysutil_sockaddr_clear(&session->p_remote_addr);
    }else
    {
        sysutil_sockaddr_clear(&session->p_port_sockaddr);
    }

}

int test_filename(struct mystr *str_arg,struct sysutil_statbuf **statbuf,int access_type)
{
     if(access(str_arg->pbuf,access_type) || sysutil_lstat(str_arg->pbuf,statbuf))
    {
        str_free(str_arg);
        sysutil_free(*statbuf);
        return 0;
    }
    return 1;
}


int prepare_port_pattern(struct mystr *str_arg,struct ftpd_session *session)
{
    int port;
    int sockfd;
    struct sysutil_sockaddr *remote = NULL;

    {
        struct mystr str_buf = INIT_MYSTR;
        struct mystr port_real = INIT_MYSTR;
        struct mystr port_imaginary = INIT_MYSTR;

        str_split_char(str_arg,&str_buf,' ');
        str_replace_char(&str_buf,',','.');
        str_split_char_reverse(&str_buf,&port_imaginary,'.');
        str_split_char_reverse(&str_buf,&port_real,'.');

        port = sysutil_atoi(port_real.pbuf) * 256 + sysutil_atoi(port_imaginary.pbuf);
        str_free(&port_real);
        str_free(&port_imaginary);

        struct sysutil_sockaddr *local = NULL;
        sockfd = sysutil_get_ipv4_sock();
        sysutil_activate_reuseaddr(sockfd);
        sysutil_activate_noblock(sockfd);

        sysutil_sockaddr_alloc_ipv4(&local);
        sysutil_sockaddr_set_any(local);
        sysutil_sockaddr_set_port(local,FTPD_DATAPORT);

        sysutil_bind(sockfd,local);
        sysutil_free(local);

        sysutil_sockaddr_alloc_ipv4(&remote);
        sysutil_sockaddr_set_ipv4addr(remote,str_buf.pbuf);
        sysutil_sockaddr_set_port(remote,port);

        str_free(&str_buf);

    }
    if(sysutil_connect_timeout(sockfd,remote,0) < 0)
    {
        sysutil_free(remote);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADPROT,"PORT connection failed.\n");
        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDPORTFAIL,NULL);
        return -1;
    }

    session->data_fd = sockfd;
    session->p_port_sockaddr = remote;
    session->is_pasv = 0;

    write_cmd_respond(FTPD_CMDWRIO,FTP_PORTOK,"PORT command successful. Consider using PASV.\n");
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDPORTOK,NULL);

    return 0;
}

int prepare_pasv_pattern(struct ftpd_session *session)
{
    int sockfd;
    int p_real,p_imaginary;
    struct mystr str_buf = INIT_MYSTR;

    {
        int port;
        srand(time(NULL));

        do {

            port = 1025 +  rand() % (65530-1024);
            p_real = port / 256;
            p_imaginary = port % 256;

        }while(sysutil_is_port_reserved(port));

        struct sysutil_sockaddr *local = NULL;
        sockfd = sysutil_get_ipv4_sock();
        sysutil_activate_noblock(sockfd);

        sysutil_sockaddr_alloc_ipv4(&local);
        sysutil_sockaddr_set_any(local);
        sysutil_sockaddr_set_port(local,port);

        sysutil_bind(sockfd,local);

        sysutil_listen(sockfd,1);
        sysutil_sockaddr_clear(&local);
    }

    {

        struct mystr port_real = INIT_MYSTR;
        struct mystr port_imaginary = INIT_MYSTR;
        char port_buf[4] = {0};

        str_alloc_text(&str_buf,"Entering Passive Mode (");
        snprintf(port_buf,4,"%d",p_real);
        str_append_text(&port_real,port_buf);

        sysutil_memclr(port_buf,4);
        snprintf(port_buf,4,"%d",p_imaginary);
        str_append_text(&port_imaginary,port_buf);

        const char *p_ip = sysutil_localnet_ipaddress(session);
        str_append_text(&str_buf,p_ip);
        //sysutil_free(p_ip);

        str_replace_char(&str_buf,'.',',');
        str_append_char(&str_buf,',');
        str_append_str(&str_buf,&port_real);
        str_append_char(&str_buf,',');
        str_append_str(&str_buf,&port_imaginary);
        str_append_text(&str_buf,")\n");

        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDPASVOK,&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_PASVOK,str_buf.pbuf);

        str_free(&str_buf);
        str_free(&port_real);
        str_free(&port_imaginary);
    }

    struct sysutil_sockaddr *remote = NULL;
    //socklen_t sock_len = sizeof(*remote);
    sysutil_sockaddr_alloc_ipv4(&remote);

    int client_fd;
    client_fd = sysutil_accept_timeout(sockfd,remote,40);
    if(client_fd < 0)
    {
        sysutil_close(sockfd);
        str_free(&str_buf);
        sysutil_sockaddr_clear(&remote);

        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDPASVFAIL,NULL);
        write_cmd_respond(FTPD_CMDWRIO,FTP_DATA_TIMEOUT,"Client connection failed.\n");
        return 0;
    }
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDPASV,NULL);

    sysutil_activate_noblock(client_fd);
    session->data_fd = client_fd;
    session->pasv_listen_fd = sockfd;
    session->p_remote_addr = remote;
    session->is_pasv = 1;

    return 1;
}

int prepare_pwd(struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;

    str_append_char(&str_buf,'\"');
    str_append_text(&str_buf,sysutil_getcwd(NULL,0));
    str_append_char(&str_buf,'\"');
    str_append_text(&str_buf," is the current directory\n");

    write_cmd_respond(FTPD_CMDWRIO,FTP_PWDOK,str_buf.pbuf);
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDPWDOK,&str_buf);
    str_free(&str_buf);

    return 1;
}


int prepare_list(struct ftpd_session *session)
{
    int retval = 0;
    const char *p_pwd = NULL;
    p_pwd = sysutil_getcwd(NULL,0);

    write_cmd_respond(FTPD_CMDWRIO,FTP_DATACONN,"Here comes the directory listing.\n");
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDLIST,NULL);
    retval = util_ls(session->data_fd,p_pwd);
    //sysutil_syslog("ls...",LOG_INFO| LOG_USER);
    if(!retval)
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Directory send Failed.\n");
        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDLISTFAIL,NULL);
        return 0;
    }

    write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDLISTOK,NULL);
    clear_data_connection(session);

    return retval;
}

int prepare_type(struct mystr *str_arg, struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    if(str_equal_text(&str_buf,"A"))
    {
        session->is_ascii = 1;
        write_cmd_respond(FTPD_CMDWRIO,FTP_TYPEOK,"apply ascii mode.\n");

//        str_free(&str_buf);
//        str_append_text(&str_buf,"apply ascii mode.\n");
//        write_internal_cmd_respond(session->parent_fd,PCMDRESPONDTYPEOK,&str_buf);
    }
    else if(str_equal_text(&str_buf,"I"))
    {
        session->is_ascii = 0;
        write_cmd_respond(FTPD_CMDWRIO,FTP_TYPEOK,"apply image mode.\n");
//        str_free(&str_buf);
//        str_append_text(&str_buf,"apply image mode.\n");
//        write_internal_cmd_respond(session->parent_fd,PCMDRESPONDTYPEOK,&str_buf);
    }

    str_free(&str_buf);
    return 1;
}

int prepare_cdup(struct ftpd_session *session)
{
    if(sysutil_chdir(".."))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"Change directory error.\n");
        return 0;
    }

    struct mystr str_buf = INIT_MYSTR;

    str_alloc_text(&str_buf,sysutil_getcwd(NULL,0));
    struct mystr_list *p_visited_dir_list = session->p_visited_dir_list;

    if(!str_list_contains_str(p_visited_dir_list,&str_buf))
    {
        str_list_add(p_visited_dir_list,&str_buf);
    }
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDCDUPOK,NULL);
    write_cmd_respond(FTPD_CMDWRIO,FTP_CWDOK,"Directory successfully changed.\n");

    return 1;
}

int prepare_cwd(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    if(sysutil_chdir(str_buf.pbuf))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"Change directory error.\n");
        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDCWDFAIL,NULL);
        str_free(&str_buf);
        return 0;
    }

    struct mystr_list *p_visited_dir_list = session->p_visited_dir_list;

    if(!str_list_contains_str(p_visited_dir_list,&str_buf))
    {
        str_list_add(p_visited_dir_list,&str_buf);
    }
    else {
        str_free(&str_buf);
    }

    write_cmd_respond(FTPD_CMDWRIO,FTP_CWDOK,"Directory successfully changed.\n");
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDCWDOK,NULL);
    return 1;
}

int prepare_mkd(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    int retval;
    retval = sysutil_mkdir(str_buf.pbuf,0775);
    if(retval < 0)
    {
        str_free(&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"Directory creation failed\n");
        return 0;
    }

    struct mystr str_responds = INIT_MYSTR;
    str_append_text(&str_responds,"The directory \"");
    str_append_str(&str_responds,&str_buf);
    str_append_text(&str_responds,"\" was successfully created.\n");

    write_cmd_respond(FTPD_CMDWRIO,FTP_MKDIROK,str_responds.pbuf);
    str_free(&str_buf);
    str_free(&str_responds);

    return 1;
}

int prepare_retr(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    struct sysutil_statbuf *statbuf = NULL;
    str_split_char(str_arg,&str_buf,' ');

    sysutil_syslog("retr",LOG_INFO | LOG_USER);
    if(!test_filename(&str_buf,&statbuf,F_OK | R_OK))
    {
        str_free(&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADSENDFILE,"no access permission.\n");
        return 0;
    }

    int sendfd = sysutil_open_file(str_buf.pbuf,kVSFSysUtilOpenReadOnly);
    if(sendfd < 0)
    {
        sysutil_free(statbuf);
        str_free(&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADSENDFILE,"open file error.\n");
    }

    session->transfer_size = statbuf->st_size;
    sysutil_free(statbuf);

    {
        sysutil_syslog("start send file",LOG_INFO | LOG_USER);
        sysutil_syslog(str_buf.pbuf,LOG_USER | LOG_INFO);

        struct mystr str_cmd = INIT_MYSTR;
        str_append_text(&str_cmd,"opening ");
        if(session->is_ascii)
            str_append_text(&str_cmd,"ASCII mode data connection for");
        else
            str_append_text(&str_cmd,"BINARY mode data connection for ");

        str_append_str(&str_cmd,&str_buf);
        str_append_text(&str_cmd," (");

        char ptr_code[32];
        snprintf(ptr_code,32,"%d",session->transfer_size);
        str_append_text(&str_cmd,ptr_code);
        str_append_text(&str_cmd," bytes).\n");

        write_cmd_respond(FTPD_CMDWRIO,FTP_DATACONN,str_cmd.pbuf);
        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDRETROK,&str_cmd);
        str_free(&str_cmd);
    }

    int retval = 0;
    retval = write_file_data(session, sendfd);
    if(retval < 0)
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADSENDNET,"Failure writing network stream.\n");
    }
    else if(retval > 0)
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Transfer complete.\n");
    }

    str_free(&str_buf);
    clear_data_connection(session);
    return 1;
}

int prepare_size(struct mystr *str_arg,struct ftpd_session *session)
{

    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');
    struct sysutil_statbuf *statbuf = NULL;

    sysutil_syslog(str_arg->pbuf,LOG_INFO | LOG_USER);
    sysutil_syslog(str_buf.pbuf,LOG_INFO | LOG_USER);

    if(!test_filename(&str_buf,&statbuf,F_OK | R_OK))
    {
        str_free(&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Incorrect filename.\n");
        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDSIZEFAIL,NULL);
        return 0;
    }
    str_free(&str_buf);

    {
        char ptr_code[64] = {'\0'};
        snprintf(ptr_code,64,"%d\n",statbuf->st_size);
        str_append_text(&str_buf,ptr_code);
        sysutil_free(statbuf);
    }

    write_cmd_respond(FTPD_CMDWRIO,FTP_SIZEOK,str_buf.pbuf);
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDSIZEOK,&str_buf);
    str_free(&str_buf);

    return 1;
}

int prepare_mdtm(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');
    struct sysutil_statbuf *statbuf = NULL;

    if(!test_filename(&str_buf,&statbuf,F_OK | R_OK))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Incorrect filename.\n");
        str_free(&str_buf);
        //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDMDTMFAIL,NULL);
        return 0;
    }
    str_free(&str_buf);

    {
        char time[32] = {0};
        struct tm *tmtime = localtime(&statbuf->st_mtime);
        strftime(time,32,"%Y%m%d%H%M%S\n",tmtime);
        str_append_text(&str_buf,time);
    }

    write_cmd_respond(FTPD_CMDWRIO,FTP_MDTMOK,str_buf.pbuf);
    //write_internal_cmd_respond(session->parent_fd,PCMDRESPONDMDTMOK,&str_buf);
    str_free(&str_buf);

    return 1;
}

int prepare_noop(struct ftpd_session *session)
{
     write_cmd_respond(FTPD_CMDWRIO,FTP_NOOPOK,"Server is alive.\n");
}


int prepare_stor(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    int recvfd = sysutil_create_or_open_file(str_buf.pbuf,0664);
    if(recvfd < 0)
    {
        str_free(&str_buf);
        clear_data_connection(session);
        write_cmd_respond(FTPD_CMDWRIO,FTP_FILEFAIL,"File create error\n");
        return 0;
    }

    int retval = 0;
    retval = read_file_data(session,recvfd,session->is_ascii);
    if(retval < 0) {
        write_cmd_respond(FTPD_CMDWRIO,FTP_DATACONN,"Failure reading network stream.\n");
    }else if(retval > 0) {
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Transfer complete.\n");
    }else {
        //write_cmd_respond(FTPD_CMDWRIO,FTP_FILEFAIL,"File receiving failed.\n");
    }

    str_free(&str_buf);
    clear_data_connection(session);

    return 1;
}

int prepare_stou(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    int recvfd = sysutil_create_file_exclusive(str_buf.pbuf);
    if(recvfd < 0)
    {
        str_free(&str_buf);
        clear_data_connection(session);
        write_cmd_respond(FTPD_CMDWRIO,FTP_FILEFAIL,"File already exist\n");
        return 0;
    }

    int retval = 0;
    retval = read_file_data(session,recvfd,session->is_ascii);
    if(retval < 0) {
        write_cmd_respond(FTPD_CMDWRIO,FTP_FILEFAIL,"File already exist or File receiving failed.\n");
    }else if(retval > 0) {
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Transfer complete.\n");
    }else {
        //write_cmd_respond(FTPD_CMDWRIO,FTP_FILEFAIL,"File receiving failed.\n");
    }

    str_free(&str_buf);
    clear_data_connection(session);
    return 1;
}


int prepare_appe(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    if(access(str_buf.pbuf,F_OK | W_OK))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"no access permission.\n");
        str_free(&str_buf);
        return 0;
    }

    int recvfd = sysutil_open_file(str_buf.pbuf,kVSFSysUtilOpenWriteOnly);
    sysutil_lseek_to(recvfd,session->restart_pos);

    if(recvfd < 0)
    {
        str_free(&str_buf);
        clear_data_connection(session);
        write_cmd_respond(FTPD_CMDWRIO,FTP_FILEFAIL,"File already exist\n");
        return 0;
    }
    write_cmd_respond(FTPD_CMDWRIO,FTP_DATACONN,"Ok to send data.\n");

    int retval = 0;
    retval = read_file_data(session,recvfd,session->is_ascii);
    if(retval < 0) {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADSENDCONN,"Transfer connection error.\n");
    }else if(retval > 0) {
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Transfer complete.\n");
    }else {
        //write_cmd_respond(FTPD_CMDWRIO,FTP_FILEFAIL,"File receiving failed.\n");
    }

    str_free(&str_buf);
    clear_data_connection(session);
    return 1;
}

int prepare_rest(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    session->restart_pos = sysutil_atoi(str_buf.pbuf);

    write_cmd_respond(FTPD_CMDWRIO,FTP_RESTOK,"File rest set successfully\n");
    str_free(&str_buf);

    return 0;
}

int prepare_rmd(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');
    struct sysutil_statbuf *statbuf = NULL;

    if(access(str_buf.pbuf,F_OK | W_OK))
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"no access permission.\n");
        str_free(&str_buf);
        return 0;
    }

//    int num = 0;
//    struct sysutil_dir *Dir;
//    struct dirent *p_dir;
//
//    Dir = sysutil_opendir(str_buf.pbuf);
//
//    while(p_dir = sysutil_next_dirent(Dir))
//    {
//        if(!str_strcmp(p_dir->d_name,".") || !str_strcmp(p_dir->d_name,".."))
//            continue;
//        num++;
//    }
//    sysutil_closedir(Dir);
//
//    if(num)
//    {
//        str_free(&str_buf);
//        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"directory not empty\n");
//        return 0;
//    }

    int retval;
    retval = sysutil_rmdir(str_buf.pbuf);
    if(retval < 0)
    {
        str_free(&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"Directory delete failed\n");
        return 0;
    }

    struct mystr str_responds = INIT_MYSTR;
    str_append_text(&str_responds,"The directory \"");
    str_append_str(&str_responds,&str_buf);
    str_append_text(&str_responds,"\" was successfully deleted.\n");

    write_cmd_respond(FTPD_CMDWRIO,FTP_RMDIROK,str_responds.pbuf);
    str_free(&str_buf);
    str_free(&str_responds);

    return 1;
}

int prepare_dele(struct mystr *str_arg,struct ftpd_session *session)
{
    struct mystr str_buf = INIT_MYSTR;
    str_split_char(str_arg,&str_buf,' ');

    if(access(str_buf.pbuf,F_OK | W_OK))
    {
        str_free(&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Incorrect filename.\n");
        return 0;
    }

    int retval = 0;
    retval = remove(str_buf.pbuf);
    if(retval < 0)
    {
        str_free(&str_buf);
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADCMD,"Try deleted file failed.\n");
        return 0;
    }

    str_free(&str_buf);
    write_cmd_respond(FTPD_CMDWRIO,FTP_DELEOK,"successfully delete.\n");

    return 0;
}


int prepare_abor(struct ftpd_session *session)
{

    session->abor_received = 1;
    if(session->data_fd == -1 && session->pasv_listen_fd == -1)
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_ABOR_NOCONN,"Abor failed, no network connection.\n");
    }
    else
    {
        write_cmd_respond(FTPD_CMDWRIO,FTP_ABOROK,"Abor success.\n");
    }

    return 0;
}



void deal_parent_respond(struct ftpd_session *session)
{
    int cmd;
    struct mystr str_buf = INIT_MYSTR;
    struct mystr str_responds = INIT_MYSTR;
    private_str_alloc_memchunk(&str_buf,NULL,FTPD_UNIXSOCK_LEN);

    get_internal_cmd_data(session->child_fd,&str_buf);

    sysutil_syslog("read internel respond",LOG_USER | LOG_INFO);
    sysutil_syslog(str_buf.pbuf,LOG_INFO | LOG_USER);

    cmd = str_get_char_at(&str_buf,0);
    if(str_buf.num_len >  1)
    {
        str_split_char(&str_buf,&str_responds,' ');
        str_append_char(&str_responds,'\n');
    }
    str_free(&str_buf);


    sysutil_syslog(str_responds.pbuf,LOG_INFO | LOG_USER);

    switch(cmd)
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
    case PCMDRESPONDPASV:
        break;
    case PCMDRESPONDPASVOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_PASVOK,str_responds.pbuf);
        deal_parent_respond(session);
        break;
    case PCMDRESPONDPASVFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_DATA_TIMEOUT,"Client connection failed.\n");
        break;
    case PCMDRESPONDSIZEOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_SIZEOK,str_responds.pbuf);
        break;
    case PCMDRESPONDSIZEFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Incorrect filename.\n");
        break;
    case PCMDRESPONDMDTMOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_MDTMOK,str_responds.pbuf);
        break;
    case PCMDRESPONDMDTMFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Incorrect filename.\n");
        break;
    case PCMDRESPONDCWDOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_CWDOK,"Directory successfully changed.\n");
        break;
    case PCMDRESPONDCWDFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Incorrect path.\n");
        break;
    case PCMDRESPONDRETROK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_DATACONN,str_responds.pbuf);
        break;
    case PCMDRESPONDRETRFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Incorrect filename.\n");
        break;
    case PCMDRESPONDSTOROK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
        break;
    case PCMDRESPONDSTORFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Directory send Failed.\n");
        break;
    case PCMDRESPONDCDUPOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_CWDOK,"Directory successfully changed.\n");
        break;
    case PCMDRESPONDLIST:
        write_cmd_respond(FTPD_CMDWRIO,FTP_DATACONN,"Here comes the directory listing.\n");
        deal_parent_respond(session);
        break;
    case PCMDRESPONDLISTOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
        break;
    case PCMDRESPONDLISTFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Directory send Failed.\n");
        break;
    case PCMDRESPONDPWDOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_PWDOK,str_responds.pbuf);
        break;
    case PCMDRESPONDTYPEOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TYPEOK,str_responds.pbuf);
        break;
    case PCMDRESPONDTYPEFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Only ASCII(A) and IMAGE(I) modes are supported..\n");
        break;
    case PCMDRESPONDMKDOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
        break;
    case PCMDRESPONDMKDFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Directory send Failed.\n");
        break;
    case PCMDRESPONDRESTOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
        break;
    case PCMDRESPONDRESTFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Directory send Failed.\n");
        break;
    case PCMDRESPONDRMDOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
        break;
    case PCMDRESPONDRMDFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Directory send Failed.\n");
        break;
    case PCMDRESPONDDELEOK:
        write_cmd_respond(FTPD_CMDWRIO,FTP_TRANSFEROK,"Directory send OK.\n");
        break;
    case PCMDRESPONDDELEFAIL:
        write_cmd_respond(FTPD_CMDWRIO,FTP_BADOPTS,"Directory send Failed.\n");
        break;
    };

    str_free(&str_responds);

}



