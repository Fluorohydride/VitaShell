#ifndef VITATP_H
#define VITATP_H

void vitatp_start_server(short port);
int check_and_run_remote_task();
int is_vitatp_running();
void vitatp_cancel_current_task();
void show_control_thread_info();

#endif
