#ifndef TWOPROCESS_H_INCLUDED
#define TWOPROCESS_H_INCLUDED

#include "session.h"

void twoprogress(struct ftpd_session *session);
int wait_client_connect(struct ftpd_session *session);
int initialize_ftpd_socket(struct sysutil_sockaddr *listen_addr);




#endif // TWOPROCESS_H_INCLUDED
