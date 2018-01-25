#ifndef DATAPROCESS_H_INCLUDED
#define DATAPROCESS_H_INCLUDED

#include "str.h"

int get_netdata(struct mystr *str_arg,char term);
int read_cmd_data(int fd,struct mystr *strbuf,unsigned int size);
void write_cmd_data(int fd,struct mystr *strbuf,unsigned int size);
void write_cmd_respond(int fd, unsigned resp_code,const char *resp_str);
int message_recv_peek(int fd,struct mystr *p_str,unsigned int datalen);
int get_request_data(int fd, struct mystr* strbuf);
void set_request_data(int fd, struct mystr* strbuf);
int get_cmd_responds();

#endif // DATAPROCESS_H_INCLUDED
