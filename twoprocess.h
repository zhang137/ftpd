#ifndef TWOPROCESS_H_INCLUDED
#define TWOPROCESS_H_INCLUDED

#include "session.h"

void twoprogress(struct ftpd_session *session);

void process_login_req(struct ftpd_session *session);

void close_parent_context(struct ftpd_session *session);

void close_child_context(struct ftpd_session *session);

void drop_all_privs();

int parse_cmd(struct ftpd_session *session, struct mystr *p_str);

#endif // TWOPROCESS_H_INCLUDED
