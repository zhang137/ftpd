#ifndef DATAPROCESS_H_INCLUDED
#define DATAPROCESS_H_INCLUDED

#include "commoncode.h"
#include "session.h"
#include "str.h"

int  get_netdata(struct mystr *str_arg,char term);
int  read_data(int fd,struct mystr *strbuf,unsigned int size);
void write_data(int fd,struct mystr *strbuf,unsigned int size);
void write_remote_transfer_data(int fd, int data_mode,const char *resp_str);
void write_local_transfer_data(int fd, int data_mode,const char *resp_str);
void write_cmd_respond(int fd, unsigned resp_code,const char *resp_str);
int read_file_data(struct ftpd_session *session, int fd,int mode);
int write_file_data(struct ftpd_session *session,  int sendfd);
int message_recv_peek(int fd,struct mystr *p_str,unsigned int datalen);
void get_internal_cmd_data(int fd, struct mystr* str_line);
void set_login_data(int fd, struct mystr* str_pass,struct mystr* str_user);
void write_internal_cmd_respond(int fd, enum PUNIXCMDSTATUS status,struct mystr *str_arg);
void write_internal_cmd_request(int fd, struct mystr* str_buf);
void recv_portmod_socket(struct ftpd_session *session);
void deal_parent_respond(struct ftpd_session *session);
void clear_data_connection(struct ftpd_session *session);
int test_filename(struct mystr *str_arg,struct sysutil_statbuf **statbuf,int access_type);

int prepare_port_pattern(struct mystr *str_arg,struct ftpd_session *session);
int prepare_pasv_pattern(struct ftpd_session *session);
int prepare_pwd(struct ftpd_session *session);
int prepare_cdup(struct ftpd_session *session);
int prepare_mkd(struct mystr *str_arg,struct ftpd_session *session);
int prepare_retr(struct mystr *str_arg,struct ftpd_session *session);
int prepare_stor(struct mystr *str_arg,struct ftpd_session *session);
int prepare_stou(struct mystr *str_arg,struct ftpd_session *session);
int prepare_rest(struct mystr *str_arg,struct ftpd_session *session);
int prepare_list(struct ftpd_session *session);
int prepare_rmd(struct mystr *str_arg,struct ftpd_session *session);
int prepare_dele(struct mystr *str_arg,struct ftpd_session *session);
int prepare_size(struct mystr *str_arg,struct ftpd_session *session);
int prepare_mdtm(struct mystr *str_arg,struct ftpd_session *session);
int prepare_noop(struct ftpd_session *session);
int prepare_abor(struct ftpd_session *session);

#endif // DATAPROCESS_H_INCLUDED
