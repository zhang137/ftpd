#ifndef TWOPROCESS_H_INCLUDED
#define TWOPROCESS_H_INCLUDED

#include "session.h"
#include "sysutil.h"

void twoprogress(struct ftpd_session *session);

void util_close_parent_context(struct ftpd_session *session);

void util_close_child_context(struct ftpd_session *session);

void delall_privilege();


#endif // TWOPROCESS_H_INCLUDED
