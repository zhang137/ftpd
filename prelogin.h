#ifndef PRELOGIN_H_INCLUDED
#define PRELOGIN_H_INCLUDED

#include "str.h"
#include "session.h"

void init_connection(struct ftpd_session *session);
struct mystr get_rpc_request(struct mystr *str_arg);

#endif // PRELOGIN_H_INCLUDED
