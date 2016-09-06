#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syslimits.h>

#include <psp2/kernel/threadmgr.h>

#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>

#include <psp2/net/net.h>
#include <psp2/net/netctl.h>

#include "main.h"
#include "utils.h"
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
#define TASK_MAX_SIZE 16

static short server_started = 0;
static void* net_buffer = NULL;
static char* file_buffer = NULL;
static int file_buffer_size = 0;

static SceNetInAddr vita_addr;
static SceUID server_thid;

static int netctl_init = -1;
static int net_init = -1;
static char network_ip[16];
static short network_port = 0;
static int server_sockfd = 0;
static int client_sockfd = 0;

static int copy_confirm = 0;
static int current_file_size = 0;
static int current_file_flag = 0;
static char current_file_name[256];
static char current_path[256];
static int current_offset;
static SceUID writing_file = -1;
static int task_canceled = 0;
int packet_count = 0;

static task_info tasks[TASK_MAX_SIZE];
static short task_begin = 0;
static short task_end = 0;

// ==============================
#define VTP_BEGIN_FILE 0x10
#define VTP_FILE_CONTENT 0x11
#define VTP_FILE_END 0x12

#define VTP_INSTALL_VPK 0x20
#define VTP_VPK_INNER_FILE 0x21
#define VTP_VPK_INNER_FILE_CONTENT 0x22
#define VTP_VPK_INNER_FILE_END 0x23

// ==============================
#define VTP_FLAG_RESTART 0x1
#define VTP_FLAG_COMPRESSED 0x2
#define VTP_FLAG_EXTRA_PERMISSION 0x4

// ==============================
#define VTPR_BEGIN_FILE 0x10
#define VTPR_FILE_CONTINUE 0x11
#define VTPR_FILE_END 0x12

// ==============================
#define TASK_WRITE_FILE 0x1
#define TASK_WRITE_FILE_DECOM 0x2

static void wait_task_to_close() {
    while(task_begin != task_end)
        sceKernelDelayThread(1000);
    if(writing_file > 0) {
        sceIoClose(writing_file);
        writing_file = -1;
    }
}

static void task_callback(short type, int* args) {
    switch(type) {
        case TASK_WRITE_FILE: {
            int buffer_size = args[1];
            if(writing_file > 0) {
                char msgbuf[512];
                sceIoWrite(writing_file, (char*)args[0], buffer_size);
                double progress = (double)((100.0f * args[2]) / (double)current_file_size);
                snprintf(msgbuf, 512, "%s\n%u/%u Bytes Finished.\n", current_file_name, args[2], current_file_size);
                sceMsgDialogProgressBarSetMsg(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (const SceChar8*)msgbuf);
		        sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (int)progress);                
            }
            free((char*)args[0]);
            break;
        }
        case TASK_WRITE_FILE_DECOM: {
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
            debugPrintf("receive file request: %s\n", current_file_name);
            while(dialog_step != DIALOG_STEP_NONE)
                sceKernelDelayThread(1000);
            initMessageDialog(SCE_MSG_DIALOG_BUTTON_TYPE_YESNO, language_container[INSTALL_WARNING]);
			dialog_step = DIALOG_STEP_REMOTE_COPY_CONFIRM;
            while(dialog_step == DIALOG_STEP_REMOTE_COPY_CONFIRM)
                sceKernelDelayThread(1000);
            debugPrintf("confirmed.\n");
            if(dialog_step == DIALOG_STEP_CANCELLED) {
                send_response(VTPR_BEGIN_FILE, 2); // user canceled
                closeWaitDialog();
                errorDialog(2);
            } else {
                int pos = 0;
                int slash_pos = -1;
                while(current_file_name[pos] != 0) {
                    if(current_file_name[pos] == '/' || current_file_name[pos] == ':')
                        slash_pos = pos;
                    pos++;
                }
                if(slash_pos == -1) {
                    send_response(VTPR_BEGIN_FILE, 3); // path error
                    closeWaitDialog();
                    errorDialog(3);
                    break;
                }
                char pre_slash = current_file_name[slash_pos];
                current_file_name[slash_pos] = 0;
                debugPrintf("check dir: %s\n", current_file_name);
                int dirres = sceIoMkdir(current_file_name, 0777);
                if (dirres <= 0 && dirres != SCE_ERROR_ERRNO_EEXIST) {
                    send_response(VTPR_BEGIN_FILE, 3); // path error
                    closeWaitDialog();
                    errorDialog(3);
                    break;
                }
                current_file_name[slash_pos] = pre_slash;
                debugPrintf("check file: %s\n", current_file_name);
                if(current_file_flag & VTP_FLAG_RESTART)
                    writing_file = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
                else {
                    writing_file = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
                    if(writing_file < 0)
                        writing_file = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
                }
                if(writing_file < 0) {
                    send_response(VTPR_BEGIN_FILE, 4); // cannot open file
                    closeWaitDialog();
                    errorDialog(4);
                    break;
                }
                current_offset = sceIoLseek(writing_file, 0, SCE_SEEK_END);
                send_response(VTPR_BEGIN_FILE, 0);
                send_response(VTPR_FILE_CONTINUE, current_offset);
                initMessageDialog(MESSAGE_DIALOG_PROGRESS_BAR, language_container[INSTALLING]);
			    dialog_step = DIALOG_STEP_REMOTE_COPY;
                task_canceled = 0;
                packet_count = 0;
                debugPrintf("begin receive file from %d.\n", current_offset);
            }
            break;
        }
        case VTP_FILE_CONTENT: {
            if(writing_file <= 0)
                break;
            if(task_canceled) {
                send_response(VTPR_BEGIN_FILE, 2);
                wait_task_to_close();
                file_buffer_size = 0;
                break;
            }
            if(data_length > FILE_BUFFER_SIZE)
                break;
            if(data_length == 0) {
                // send offset
                debugPrintf("receive offset request. pf=%d, pkt=%d\n", current_offset, packet_count);
                send_response(VTPR_FILE_CONTINUE, current_offset);
            } else {
                packet_count++;
                if(file_buffer_size + data_length > FILE_BUFFER_SIZE) {
                    debugPrintf("add writing task %d bytes. of=%d\n", file_buffer_size, current_offset);
                    char* buffer = malloc(file_buffer_size);
                    memcpy(buffer, file_buffer, file_buffer_size);
                    add_task(TASK_WRITE_FILE, (int)buffer, file_buffer_size, current_offset);
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
                char* buffer = malloc(file_buffer_size);
                memcpy(buffer, file_buffer, file_buffer_size);
                debugPrintf("add final writing task %d bytes\n", file_buffer_size);
                add_task(TASK_WRITE_FILE, (int)buffer, file_buffer_size, current_offset);
                file_buffer_size = 0;
            }
            closeWaitDialog();
            debugPrintf("receive file end. pkt=%d offset=%d\n", packet_count, current_offset);
            infoDialog("Remote Copy Finished.");
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
    file_buffer = malloc(FILE_BUFFER_SIZE);
    file_buffer_size = 0;
    while (1) {
        // only 1 remote manager is allowed
        SceNetSockaddrIn clientaddr;
        unsigned int addrlen = sizeof(clientaddr);
        client_sockfd = sceNetAccept(server_sockfd, (SceNetSockaddr *)&clientaddr, &addrlen);
        if (client_sockfd >= 0) {
            debugPrintf("client connected.\n");
            char recv_buffer[4096];
            int recv_offset = 0;
            int hdr_size = 0;
            int data_size = 0;
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
                            memmove(recv_buffer, &recv_buffer[offset], left_data_size);
                            recv_offset = left_data_size;
                            break;
                        }
                        handle_packet(hdr.type, &recv_buffer[offset + 4], hdr.length - 4);
                        offset += hdr.length;
                        hdr_size += 4;
                        data_size += hdr.length - 4;
                    }
                } else {
                    // =0 -- connection closed
                    // <0 -- error
                    break;
                }
            }
            debugPrintf("client disconnected. hd=%d, ds=%d\n", hdr_size, data_size);
            sceNetSocketClose(client_sockfd);
            // clear status
            current_file_size = 0;
            current_file_flag = 0;
            wait_task_to_close();
        } else {
            // accept error
            break;
        }
    }
exit:
    if(file_buffer) {
        free(file_buffer);
        file_buffer = NULL;
    }
    file_buffer_size = 0;
    server_started = 0;
    infoDialog("Network Test end");
    sceKernelExitDeleteThread(0);
    return 0;
}

int vitatp_begin_server(short port) {
    int ret;
    int i;
    SceNetInitParam initparam;
    SceNetCtlInfo info;

    if (server_started) {
        return -1;
    }

    /* Init Net */
    ret = sceNetShowNetstat();
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

    /* Init NetCtl */
    ret = netctl_init = sceNetCtlInit();
    // 0x80412102 = NET_CTL_ERROR_NOT_TERMINATED
    if (netctl_init < 0 && netctl_init != 0x80412102)
        goto error_netctlinit;

    /* Get IP address */
    ret = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
    if (ret < 0)
        goto error_netctlgetinfo;

    /* Return data */
    strcpy(network_ip, info.ip_address);

    /* Save the IP of PSVita to a global variable */
    sceNetInetPton(SCE_NET_AF_INET, info.ip_address, &vita_addr);

    /* Create server thread */
    server_thid = sceKernelCreateThread("remote_control_thread",
        control_thread, 0x10000100, 0x10000, 0, 0, NULL);

    network_port = port;

    /* Start the server thread */
    infoDialog("Network Test begin");
    sceKernelStartThread(server_thid, 0, NULL);

    server_started = 1;

    return 0;

error_netctlgetinfo:
    if (netctl_init == 0) {
        sceNetCtlTerm();
        netctl_init = -1;
    }
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
    infoDialog("Network Test error.");
    return ret;
}

int vitatp_end_server() {
    if (!server_started)
        return -1;
    /* In order to "stop" the blocking sceNetAccept,
    * we have to close the server socket; this way
    * the accept call will return an error */
    sceNetSocketClose(server_sockfd);

    /* Wait until the server threads ends */
    sceKernelWaitThreadEnd(server_thid, NULL, NULL);

    if (netctl_init == 0)
        sceNetCtlTerm();
    if (net_init == 0)
        sceNetTerm();
    if (net_buffer)
        free(net_buffer);

    netctl_init = -1;
    net_init = -1;
    net_buffer = NULL;
    server_started = 0;
    return 0;
}

void check_and_run_remote_task() {
    while(task_begin != task_end) {
        debugPrintf("run task %d / %d.\n", task_begin, task_end);
        task_callback(tasks[task_begin].type, tasks[task_begin].args);
        task_begin = (task_begin + 1) % TASK_MAX_SIZE;
    }
}

int is_vitatp_running() {
    return server_started;
}

void vitatp_cancel_current_task() {
    task_canceled = 1;
}
