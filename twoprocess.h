#ifndef TWOPROCESS_H_INCLUDED
#define TWOPROCESS_H_INCLUDED

#include "session.h"

void twoprogress(struct ftpd_session *session);

void set_private_unix_socket(struct ftpd_session *session);

void close_parent_context(struct ftpd_session *session);

void close_child_context(struct ftpd_session *session);

void del_privilege();

void wait_req();

#endif // TWOPROCESS_H_INCLUDED
