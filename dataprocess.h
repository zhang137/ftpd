#ifndef DATAPROCESS_H_INCLUDED
#define DATAPROCESS_H_INCLUDED

#include "str.h"

int get_netdata(struct mystr *str_arg,int *end_point,char term);
int read_cmd_data(int fd,struct mystr *strbuf,unsigned int size);
void write_cmd_data(int fd,struct mystr *strbuf,unsigned int size);
int write_cmd_respond(int fd, unsigned resp_code,const char *resp_str);

#endif // DATAPROCESS_H_INCLUDED
