#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syslimits.h>
#include <zlib.h>

#include <psp2/kernel/threadmgr.h>

#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>

#include <psp2/net/net.h>
#include <psp2/net/netctl.h>

#include "main.h"
#include "utils.h"
#include "file.h"
#include "io_process.h"
#include "language.h"
#include "message_dialog.h"
#include "package_installer.h"
#include "vitatp.h"

typedef struct {
    short length;
    short type;
} pkt_header;

typedef struct {
    short length;
    short type;
    int result;
} pkt_response;

typedef struct {
    short type;
    int args[3];
} task_info;

#define NET_BUFFER_SIZE 4*1024*1024
#define FILE_BUFFER_SIZE 2*1024*1024
#define RECV_BUFFER_SIZE 16 * 1024
#define DECOM_BUFFER_SIZE 1024 * 1024
#define TASK_MAX_SIZE 16

static short server_started = 0;
static void* net_buffer = NULL;
static char* file_buffer = NULL;
static int file_buffer_size = 0;

static SceUID server_thid;

static int netctl_init = -1;
static int net_init = -1;
static char network_ip[16];
static short network_port = 0;
static int server_sockfd = 0;
static int client_sockfd = 0;

static int current_file_size = 0;
static int current_file_flag = 0;
static char current_file_name[256];
static char current_path[256];
static int current_offset;
static SceUID writing_file = -1;
static int task_canceled = 0;
static z_stream comp_stream;
static unsigned char* decom_buffer = NULL;

static int vpk_status = 0;
static int vpk_flag = 0;
static long long vpk_size = 0;
static long long vpk_size_finished = 0;

static task_info tasks[TASK_MAX_SIZE];
static short task_begin = 0;
static short task_end = 0;
static int need_refresh = 0;

// ==============================
#define VTP_BEGIN_FILE 0x10
#define VTP_FILE_CONTENT 0x11
#define VTP_FILE_END 0x12
#define VTP_INSTALL_VPK 0x13
#define VTP_INSTALL_VPK_END 0x14

// ==============================
#define VTP_FLAG_RESTART 0x1
#define VTP_FLAG_COMPRESSED_ZLIB 0x2
#define VTP_FLAG_COMPRESSED_LZMA 0x4
#define VTP_FLAG_EXTRA_PERMISSION 0x8

// ==============================
#define VTPR_BEGIN_FILE 0x18
#define VTPR_FILE_CONTINUE 0x19
#define VTPR_FILE_END 0x1A
#define VTPR_INSTALL_VPK 0x1B
#define VTPR_INSTALL_VPK_END 0x1C

// ==============================
#define TASK_WRITE_FILE 0x1
#define TASK_WRITE_FILE_ZLIB 0x2
#define TASK_WRITE_FILE_LZMA 0x3

static void wait_task_and_close_file() {
    while(task_begin != task_end)
        sceKernelDelayThread(1000);
    if(writing_file > 0) {
        sceIoClose(writing_file);
        writing_file = -1;
        if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB)
            inflateEnd(&comp_stream);
        if(decom_buffer)
            free(decom_buffer);
    }
    if(file_buffer) {
        free(file_buffer);
        file_buffer = NULL;
    }
    file_buffer_size = 0;
    current_file_flag = 0;
}

static void wait_task_and_clear_status() {
    wait_task_and_close_file();
    vpk_status = 0;
    closeWaitDialog();
    powerUnlock();
}

static void UpdateProgress(int current_size) {
    // char msgbuf[512];
    if(vpk_status > 0) {
        if(vpk_size == 0)
            return;
        double progress = (double)((100.0f * (vpk_size_finished + current_size)) / (double)(vpk_size));
        // snprintf(msgbuf, 512, "%s\n%u / %u.\n", current_file_name, current_size, current_file_size);
        // sceMsgDialogProgressBarSetMsg(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (const SceChar8*)msgbuf);
        sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (int)progress);
    } else {
        if(current_file_size == 0)
            return;
        double progress = (double)((100.0f * current_size) / (double)current_file_size);
        // snprintf(msgbuf, 512, "%s\n%u / %u.\n", current_file_name, current_size, current_file_size);
        // sceMsgDialogProgressBarSetMsg(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (const SceChar8*)msgbuf);
		sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (int)progress);
    }
}

static void task_callback(short type, int* args) {
    switch(type) {
        case TASK_WRITE_FILE: {
            int buffer_size = args[1];
            if(writing_file > 0) {
                sceIoWrite(writing_file, (char*)args[0], buffer_size);
                UpdateProgress(args[2]);
            }
            free((char*)args[0]);
            break;
        }
        case TASK_WRITE_FILE_ZLIB: {
            unsigned char* buffer = (unsigned char*)args[0];
            int buffer_size = args[1];            
            if(writing_file > 0) {
                comp_stream.next_in = buffer;
                comp_stream.avail_in = buffer_size;
                do {
                    comp_stream.avail_out = DECOM_BUFFER_SIZE;
                    comp_stream.next_out = decom_buffer;
                    int res = inflate(&comp_stream, Z_NO_FLUSH);
                    if(res > 1) {
                        // todo: error stream
                        break;
                    }
                    int out_sz = DECOM_BUFFER_SIZE - comp_stream.avail_out;
                    if(out_sz > 0)
                        sceIoWrite(writing_file, decom_buffer, out_sz);
                } while(comp_stream.avail_out == 0);
                UpdateProgress(args[2]);
            }
            free(buffer);
            break;
        }
        case TASK_WRITE_FILE_LZMA: {
            free((char*)args[0]);
            break;
        }
    }
}

static void add_task(short type, int arg1, int arg2, int arg3) {
    while(((task_end + 1) % TASK_MAX_SIZE) == task_begin)
        sceKernelDelayThread(1000);
    tasks[task_end].type = type;
    tasks[task_end].args[0] = arg1;
    tasks[task_end].args[1] = arg2;
    tasks[task_end].args[2] = arg3;
    task_end = (task_end + 1) % TASK_MAX_SIZE;
}

static void send_to_client(short pkt_type, char* data, short data_length) {
    static pkt_header hdr;
    hdr.length = 4 + data_length;
    hdr.type = pkt_type;
    sceNetSend(client_sockfd, &hdr, 4, 0);
    if(data && data_length > 0)
        sceNetSend(client_sockfd, data, data_length, 0);
}

static void send_response(short pkt_type, int result) {
    static pkt_response resp;
    resp.length = 8;
    resp.type = pkt_type;
    resp.result = result;
    sceNetSend(client_sockfd, &resp, 8, 0);
}

static void handle_packet(short pkt_type, char* data, short data_length) {
    switch(pkt_type) {
        case VTP_BEGIN_FILE: {
            // int file_size, int flag, char* file_name
            if(data_length <= 8)
                break;
            if(writing_file > 0) {
                send_response(VTPR_BEGIN_FILE, 1); // VTP_FILE_END should be send before a new file
                break;
            }
            memcpy(&current_file_size, data, 4);
            memcpy(&current_file_flag, &data[4], 4);
            strncpy(current_file_name, &data[8], 256);
            current_file_name[255] = 0;
            // if(vpk_status == 0) {
            //     while(dialog_step != DIALOG_STEP_NONE)
            //         sceKernelDelayThread(1000);
            //     initMessageDialog(SCE_MSG_DIALOG_BUTTON_TYPE_YESNO, language_container[INSTALL_WARNING]);
            //     dialog_step = DIALOG_STEP_REMOTE_COPY_CONFIRM;
            //     while(dialog_step == DIALOG_STEP_REMOTE_COPY_CONFIRM)
            //         sceKernelDelayThread(1000);
            //     if(dialog_step == DIALOG_STEP_CANCELLED) {
            //         send_response(VTPR_BEGIN_FILE, 2); // user canceled
            //         closeWaitDialog();
            //         errorDialog(-1);
            //         break;
            //     }
            // }

            // create dir
            int path_err = 0;
            char* pdir = current_file_name;
            while(*pdir != 0) {
                if(*pdir == '/') {
                    *pdir = 0;
                    int dirres = sceIoMkdir(current_file_name, 0777);
                    if (dirres < 0 && dirres != SCE_ERROR_ERRNO_EEXIST) {
                        path_err = 1;
                    }
                    *pdir = '/';
                    if(path_err)
                        break;
                }
                pdir++;
            }
            if(path_err) {
                send_response(VTPR_BEGIN_FILE, 3); // path error
                if(vpk_status == 0) {
                    closeWaitDialog();
                    errorDialog(-1);
                }
                break;
            }
            // try open file
            if(current_file_flag & VTP_FLAG_RESTART) {
                writing_file = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
                current_offset = 0;
            } else {
                writing_file = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
                if(writing_file < 0)
                    writing_file = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
                current_offset = sceIoLseek(writing_file, 0, SCE_SEEK_END);
            }
            if(writing_file < 0) {
                send_response(VTPR_BEGIN_FILE, 4); // cannot open file
                if(vpk_status == 0) {
                    closeWaitDialog();
                    errorDialog(-1);
                }
                break;
            }
            send_response(VTPR_BEGIN_FILE, 0);
            send_response(VTPR_FILE_CONTINUE, current_offset);
            if(vpk_status == 0) {
                initMessageDialog(MESSAGE_DIALOG_PROGRESS_BAR, language_container[COPYING]);
                dialog_step = DIALOG_STEP_REMOTE_COPY;
                powerLock();
            }
            task_canceled = 0;
            file_buffer = malloc(FILE_BUFFER_SIZE);
            file_buffer_size = 0;
            if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB) {
                memset(&comp_stream, 0, sizeof(comp_stream));
                // inflate raw data
                inflateInit2(&comp_stream, -15);
                decom_buffer = (unsigned char*)malloc(DECOM_BUFFER_SIZE);
            }
            break;
        }
        case VTP_FILE_CONTENT: {
            if(writing_file <= 0)
                break;
            if(task_canceled) {
                send_response(VTPR_BEGIN_FILE, 2);
                wait_task_and_clear_status();
                break;
            }
            if(data_length > FILE_BUFFER_SIZE)
                break;
            if(data_length == 0) {
                // send offset
                send_response(VTPR_FILE_CONTINUE, current_offset);
            } else {
                if(file_buffer_size + data_length > FILE_BUFFER_SIZE) {
                    int taskid = TASK_WRITE_FILE;
                    if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB)
                        taskid = TASK_WRITE_FILE_ZLIB;
                    if(current_file_flag & VTP_FLAG_COMPRESSED_LZMA)
                        taskid = TASK_WRITE_FILE_LZMA;
                    add_task(taskid, (int)file_buffer, file_buffer_size, current_offset);
                    file_buffer = malloc(file_buffer_size);
                    file_buffer_size = 0;
                }
                memcpy(&file_buffer[file_buffer_size], data, data_length);
                file_buffer_size += data_length;
                current_offset += data_length;
            }
            break;
        }
        case VTP_FILE_END: {
            if(writing_file <= 0)
                break;
            send_response(VTPR_FILE_END, 0);
            if(file_buffer_size > 0) {
                int taskid = TASK_WRITE_FILE;
                if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB)
                    taskid = TASK_WRITE_FILE_ZLIB;
                if(current_file_flag & VTP_FLAG_COMPRESSED_LZMA)
                    taskid = TASK_WRITE_FILE_LZMA;
                add_task(taskid, (int)file_buffer, file_buffer_size, current_offset);
                file_buffer = NULL;
                file_buffer_size = 0;
            }
            wait_task_and_close_file();
            if(vpk_status == 0) {
                sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, 100);
                sceKernelDelayThread(COUNTUP_WAIT);
                closeWaitDialog();
                powerUnlock();
                need_refresh = 1;
            } else {
                vpk_size_finished += current_file_size;
                UpdateProgress(0);
            }
            break;
        }
        case VTP_INSTALL_VPK: {
            // int64 all_size
            // int flag
            if(data_length < 12)
                break;
            if(vpk_status > 0) {
                send_response(VTPR_INSTALL_VPK, 1); // VTP_INSTALL_VPK_END should be send before a new vpk
                break;
            }
            while(dialog_step != DIALOG_STEP_NONE)
                sceKernelDelayThread(1000);
            memcpy(&vpk_size, data, 8);
            memcpy(&vpk_flag, &data[8], 4);
            if(vpk_flag & VTP_FLAG_EXTRA_PERMISSION) {
                initMessageDialog(SCE_MSG_DIALOG_BUTTON_TYPE_YESNO, language_container[INSTALL_WARNING]);
            } else {
                initMessageDialog(SCE_MSG_DIALOG_BUTTON_TYPE_YESNO, language_container[INSTALL_QUESTION]);
            }
			dialog_step = DIALOG_STEP_REMOTE_COPY_CONFIRM;
            while(dialog_step == DIALOG_STEP_REMOTE_COPY_CONFIRM)
                sceKernelDelayThread(1000);
            if(dialog_step == DIALOG_STEP_CANCELLED) {
                send_response(VTPR_INSTALL_VPK, 2); // user canceled
                break;
            } else {
                vpk_status = 1;
                removePath(PACKAGE_PARENT, NULL, 0, NULL, NULL);
	            sceIoMkdir(PACKAGE_PARENT, 0777);
                send_response(VTPR_INSTALL_VPK, 0);
                initMessageDialog(MESSAGE_DIALOG_PROGRESS_BAR, language_container[INSTALLING]);
                dialog_step = DIALOG_STEP_REMOTE_COPY;
                powerLock();
            }
            break;
        }
        case VTP_INSTALL_VPK_END: {
            if(vpk_status == 0)
                break;
            vpk_status = 0;
            if (makeHeadBin() < 0) {
                closeWaitDialog();
                errorDialog(-1);
                break;
            }
            if (promote(PACKAGE_DIR) < 0) {
                closeWaitDialog();
                errorDialog(-1);
                break;
            }
            send_response(VTPR_INSTALL_VPK_END, 0);
            sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, 100);
            sceKernelDelayThread(COUNTUP_WAIT);
            closeWaitDialog();
            sceKernelDelayThread(DIALOG_WAIT);
            infoDialog("Remote install success");
            powerUnlock();
            break;
        }
    }
}

static int control_thread(SceSize args, void *argp) {
    SceNetSockaddrIn serveraddr;
    serveraddr.sin_family = SCE_NET_AF_INET;
    serveraddr.sin_addr.s_addr = sceNetHtonl(SCE_NET_INADDR_ANY);
    serveraddr.sin_port = sceNetHtons(network_port);

    server_sockfd = sceNetSocket("control socket", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, SCE_NET_IPPROTO_TCP);
    if(server_sockfd == -1)
        goto exit;
    if(sceNetBind(server_sockfd, (SceNetSockaddr *)&serveraddr, sizeof(serveraddr)) != 0)
        goto exit;
    if(sceNetListen(server_sockfd, 128) != 0)
        goto exit;

    SceNetCtlInfo info;
    sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
    strcpy(network_ip, info.ip_address);

    server_started = 1;
    char* recv_buffer = malloc(RECV_BUFFER_SIZE);
    while (1) {
        // only 1 remote manager is allowed
        SceNetSockaddrIn clientaddr;
        unsigned int addrlen = sizeof(clientaddr);
        client_sockfd = sceNetAccept(server_sockfd, (SceNetSockaddr *)&clientaddr, &addrlen);
        if (client_sockfd >= 0) {
            int recv_offset = 0;
            pkt_header hdr;
            // begin recv
            while (1) {
                int recv_size = sceNetRecv(client_sockfd, &recv_buffer[recv_offset], 4096 - recv_offset, 0);
                if (recv_size > 0) {
                    recv_offset += recv_size;
                    int offset = 0;
                    while(offset + 4 <= recv_offset) {
                        int left_data_size = recv_offset - offset;  // include header
                        memcpy(&hdr, &recv_buffer[offset], 4);
                        if(hdr.length < 4 || hdr.length > 1500) {
                            // packet length error, skip
                            offset += 2;
                            continue;
                        };
                        if(hdr.length > left_data_size) {
                            // need receive more data
                            break;
                        }
                        handle_packet(hdr.type, &recv_buffer[offset + 4], hdr.length - 4);
                        offset += hdr.length;
                    }
                    if(offset != recv_offset)
                        memmove(recv_buffer, &recv_buffer[offset], recv_offset - offset);
                    recv_offset -= offset;
                } else {
                    // =0 -- connection closed
                    // <0 -- error
                    break;
                }
            }
            sceNetSocketClose(client_sockfd);
            // clear status
            wait_task_and_clear_status();
        } else {
            // accept error
            break;
        }
    }
    free(recv_buffer);
exit:
    if(server_sockfd != -1)
        sceNetSocketClose(server_sockfd);
    server_started = 0;
    sceKernelExitDeleteThread(0);
    return 0;
}

static int control_thread_daemon(SceSize args, void *argp) {
    while(1) {
        if(server_started == 0) {
            server_thid = sceKernelCreateThread("remote_control_thread",
                control_thread, 0x10000100, 0x10000, 0, 0, NULL);
            sceKernelStartThread(server_thid, 0, NULL);
        }
        sceKernelDelayThread(500 * 1000);
    }
    // useless
    return 0;
}

void vitatp_start_server(short port) {
    SceNetInitParam initparam;

    // Init Net
    int ret = sceNetShowNetstat();
    if (ret == 0) {
        net_init = -1;
    } else if (ret == SCE_NET_ERROR_ENOTINIT) {
        net_buffer = malloc(NET_BUFFER_SIZE);

        initparam.memory = net_buffer;
        initparam.size = NET_BUFFER_SIZE;
        initparam.flags = 0;

        ret = net_init = sceNetInit(&initparam);
        if (net_init < 0)
            goto error_netinit;
    } else {
        goto error_netstat;
    }

    // Init NetCtl
    netctl_init = sceNetCtlInit();
    // 0x80412102 = NET_CTL_ERROR_NOT_TERMINATED
    if (netctl_init < 0 && netctl_init != 0x80412102)
        goto error_netctlinit;

    network_port = port;

    // Create control thread daemon
    SceUID daemon_id = sceKernelCreateThread("remote_control_thread_daemon",
        control_thread_daemon, 0x10000100, 0x10000, 0, 0, NULL);
    sceKernelStartThread(daemon_id, 0, NULL);

    return;

error_netctlinit:
    if (net_init == 0) {
        sceNetTerm();
        net_init = -1;
    }
error_netinit:
    if (net_buffer) {
        free(net_buffer);
        net_buffer = NULL;
    }
error_netstat:
    debugPrintf("network setting error.\n");
    return;
}

int check_and_run_remote_task() {
    while(task_begin != task_end) {
        task_callback(tasks[task_begin].type, tasks[task_begin].args);
        task_begin = (task_begin + 1) % TASK_MAX_SIZE;
    }
    if(need_refresh) {
        need_refresh = 0;
        return 1;
    }
    return 0;
}

int is_vitatp_running() {
    return server_started;
}

void vitatp_cancel_current_task() {
    task_canceled = 1;
}

void show_control_thread_info() {
    infoDialog("%s:%d", network_ip, network_port);
}
