#ifndef DATAPROCESS_H_INCLUDED
#define DATAPROCESS_H_INCLUDED

#include "commoncode.h"
#include "session.h"
#include "str.h"

int get_cmd_responds(int fd);
int get_netdata(struct mystr *str_arg,char term);
int read_cmd_data(int fd,struct mystr *strbuf,unsigned int size);
void write_cmd_data(int fd,struct mystr *strbuf,unsigned int size);
void write_cmd_respond(int fd, unsigned resp_code,const char *resp_str);
int message_recv_peek(int fd,struct mystr *p_str,unsigned int datalen);
void get_request_data(int fd, struct mystr* str_buf);
void set_login_data(int fd, struct mystr* str_pass,struct mystr* str_user);
void set_respond_data(int fd, enum PUNIXLOGINSTATUS status);
void recv_portmod_socket(struct ftpd_session *session);
void deal_parent_respond(struct ftpd_session *session);

int prepare_port_pattern(struct mystr *str_arg,struct ftpd_session *session);
int prepare_pasv_pattern(struct ftpd_session *session);
int prepare_pwd(struct ftpd_session *session);
int prepare_cdup(struct ftpd_session *session);
int prepare_mkd(struct mystr *str_arg,struct ftpd_session *session);
int prepare_retr(struct mystr *str_arg,struct ftpd_session *session);
int prepare_stor(struct mystr *str_arg,struct ftpd_session *session);
int prepare_rest(struct mystr *str_arg,struct ftpd_session *session);
int prepare_list(struct ftpd_session *session);

#endif // DATAPROCESS_H_INCLUDED
