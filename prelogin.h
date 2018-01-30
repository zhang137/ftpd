#ifndef PRELOGIN_H_INCLUDED
#define PRELOGIN_H_INCLUDED

#include "str.h"
#include "session.h"

void init_connection(struct ftpd_session *session);
struct mystr get_rpc_request(struct mystr *str_arg);
int prepare_login(struct mystr *str_arg,struct ftpd_session *session);
int prepare_port_pattern(struct mystr *str_arg,struct ftpd_session *session);
int prepare_pasv_pattern(struct mystr *str_arg,struct ftpd_session *session);
void login_user(struct ftpd_session *session);
void user_common_deal(struct ftpd_session *session);
void common_request(struct ftpd_session *session);
void wait_data_connection(struct ftpd_session *session);

#endif // PRELOGIN_H_INCLUDED
