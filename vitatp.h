#ifndef VITATP_H
#define VITATP_H

int vitatp_begin_server(short port);
int vitatp_end_server();
void check_and_run_remote_task();
int is_vitatp_running();
void vitatp_cancel_current_task();

#endif
