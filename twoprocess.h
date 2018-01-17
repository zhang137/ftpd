#ifndef TWOPROCESS_H_INCLUDED
#define TWOPROCESS_H_INCLUDED

#include "session.h"
#include "sysutil.h"

void twoprogress(struct ftpd_session *session);
int wait_client_connect(struct session *session);
int initialize_ftpd_listen_socket();




#endif // TWOPROCESS_H_INCLUDED
