#ifndef UTIL_H_INCLUDED
#define UTIL_H_INCLUDED

#include "session.h"

void standalone_socket(struct ftpd_session *session);

void init_session();

void load_default_config();

void util_client_dup2(int fd);


#endif // UTIL_H_INCLUDED
