#ifndef TWOPROCESS_H_INCLUDED
#define TWOPROCESS_H_INCLUDED

#include "session.h"

void twoprogress(struct ftpd_session *session);

void deal_private_req(struct ftpd_session *session);

void close_parent_context(struct ftpd_session *session);

void close_child_context(struct ftpd_session *session);

void del_privilege();


#endif // TWOPROCESS_H_INCLUDED
