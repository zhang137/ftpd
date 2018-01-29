#ifndef PRELOGIN_H_INCLUDED
#define PRELOGIN_H_INCLUDED

#include "str.h"
#include "session.h"

void init_connection(struct ftpd_session *session);
struct mystr get_rpc_request(struct mystr *str_arg);
int prepare_login(struct mystr *str_arg,struct ftpd_session *session);
void login_user(struct ftpd_session *session);
void ready_to_login(struct ftpd_session *session);

#endif // PRELOGIN_H_INCLUDED
