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
    int result1;
    int result2;
} pkt_response;

typedef struct {
    short type;
    int args[3];
} task_info;

#define NET_BUFFER_SIZE 4 * 1024 * 1024
#define FILE_BUFFER_SIZE 2 * 1024 * 1024
#define RECV_BUFFER_SIZE 16 * 1024
#define DECOM_BUFFER_SIZE 2 * 1024 * 1024
#define TASK_MAX_SIZE 64

static short server_started = 0;
static void* net_buffer = NULL;
static char* file_buffer = NULL;
static int file_buffer_size = 0;

static SceUID server_thid;

static int netctl_init = -1;
static int net_init = -1;
static short network_port = 0;
static int server_sockfd = 0;
static int client_sockfd = 0;

static int current_file_size = 0;
static int current_file_flag = 0;
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
#define VTP_VPK_CONTENT 0x14
#define VTP_INSTALL_VPK_END 0x15

// ==============================
#define VTP_FLAG_RESTART 0x1
#define VTP_FLAG_COMPRESSED_ZLIB 0x2
#define VTP_FLAG_COMPRESSED_LZMA 0x4
#define VTP_FLAG_EXTRA_PERMISSION 0x8
#define VTP_FLAG_NO_PROGRESS 0x10

// ==============================
#define VTPR_BEGIN_FILE 0x18
#define VTPR_FILE_CONTINUE 0x19
#define VTPR_FILE_END 0x1A
#define VTPR_INSTALL_VPK 0x1B
#define VTPR_VPK_CONTINUE 0x1C
#define VTPR_INSTALL_VPK_END 0x1D

// ==============================
#define TASK_BEGIN_WRITE_FILE 0x1
#define TASK_WRITE_FILE 0x2
#define TASK_WRITE_FILE_ZLIB 0x3
#define TASK_WRITE_FILE_LZMA 0x4
#define TASK_CLOSE_FILE 0x5
#define TASK_VPK_BUFFER 0x8

static void wait_task_and_close_file() {
    while(task_begin != task_end)
        sceKernelDelayThread(1000);
    if(writing_file > 0) {
        sceIoClose(writing_file);
        writing_file = -1;
        if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB)
            inflateEnd(&comp_stream);
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
        sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (int)progress);
    } else {
        if(current_file_size == 0)
            return;
        double progress = (double)((100.0f * current_size) / (double)current_file_size);
		sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, (int)progress);
    }
}

typedef union {
    short length;
    unsigned char lbuf[2];
} vpk_name_len_s;

typedef union {
    int length;
    unsigned char lbuf[4];
} vpk_file_len_s;

static int create_path(char* filename) {
    char* pdir = filename;
    int path_err = 0;
    while(*pdir != 0) {
        if(*pdir == '/') {
            *pdir = 0;
            int dirres = sceIoMkdir(filename, 0777);
            if (dirres < 0 && dirres != SCE_ERROR_ERRNO_EEXIST)
                path_err = 1;
            *pdir = '/';
            if(path_err)
                return 1;
        }
        pdir++;
    }
    return 0;
}

static void task_callback(short type, int* args) {
    static int vpk_buffer_status = 0;
    static int vpk_left_bytes = 2;
    static vpk_name_len_s name_len;
    static vpk_file_len_s file_len;
    static char vpk_name[1024];    
    switch(type) {
        case TASK_BEGIN_WRITE_FILE: {
            writing_file = args[0];
            current_file_size = args[1];
            current_file_flag = args[2];
            if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB) {
                memset(&comp_stream, 0, sizeof(comp_stream));
                // inflate raw data
                inflateInit2(&comp_stream, -15);
            }
            break;
        }
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
        case TASK_CLOSE_FILE: {
            if(writing_file >= 0) {
                if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB)
                    inflateEnd(&comp_stream);
                sceIoClose(writing_file);
                writing_file = -1;
            }
            current_file_size = 0;
            current_file_flag = 0;
            break;
        }
        case TASK_VPK_BUFFER : {
            unsigned char* buffer = (unsigned char*)args[0];
            int buffer_size = args[1];
            int offset = 0;
            while(offset < buffer_size) {
                int left_size = buffer_size - offset;
                switch(vpk_buffer_status) {                    
                    case 0: {
                        if(left_size >= vpk_left_bytes) {
                            memcpy(&name_len.lbuf[2 - vpk_left_bytes], &buffer[offset], vpk_left_bytes);
                            offset += vpk_left_bytes;
                            vpk_left_bytes = name_len.length;
                            vpk_buffer_status = 1;
                        } else {
                            memcpy(&name_len.lbuf[2 - vpk_left_bytes], &buffer[offset], left_size);
                            vpk_left_bytes -= left_size;
                            offset = buffer_size;
                        }
                        break;
                    }
                    case 1: {
                        if(left_size >= vpk_left_bytes) {
                            memcpy(&vpk_name[name_len.length - vpk_left_bytes], &buffer[offset], vpk_left_bytes);
                            vpk_name[name_len.length] = 0;
                            offset += vpk_left_bytes;
                            vpk_left_bytes = 4;
                            vpk_buffer_status = 2;
                        } else {
                            memcpy(&name_len.lbuf[name_len.length - vpk_left_bytes], &buffer[offset], left_size);
                            vpk_left_bytes -= left_size;
                            offset = buffer_size;
                        }
                        break;
                    }
                    case 2: {
                        if(left_size >= vpk_left_bytes) {
                            memcpy(&file_len.lbuf[4 - vpk_left_bytes], &buffer[offset], vpk_left_bytes);
                            offset += vpk_left_bytes;
                            vpk_left_bytes = file_len.length;
                            if(vpk_left_bytes == 0) {
                                vpk_buffer_status = 0;
                                vpk_left_bytes = 2;
                            } else {
                                vpk_buffer_status = 3;
                                memset(&comp_stream, 0, sizeof(comp_stream));
                                inflateInit2(&comp_stream, -15);
                                create_path(vpk_name);
                                writing_file = sceIoOpen(vpk_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
                            }
                        } else {
                            memcpy(&file_len.lbuf[4 - vpk_left_bytes], &buffer[offset], left_size);
                            vpk_left_bytes -= left_size;
                            offset = buffer_size;
                        }
                        break;
                    }
                    case 3: {
                        int available = (left_size < vpk_left_bytes) ? left_size : vpk_left_bytes;
                        vpk_left_bytes -= available;
                        comp_stream.next_in = &buffer[offset];
                        comp_stream.avail_in = available;
                        do {
                            comp_stream.avail_out = DECOM_BUFFER_SIZE;
                            comp_stream.next_out = decom_buffer;
                            int res = inflate(&comp_stream, Z_NO_FLUSH);
                            if(res > 1) {
                                // todo: error stream
                                break;
                            }
                            int out_sz = DECOM_BUFFER_SIZE - comp_stream.avail_out;
                            if(out_sz > 0 && writing_file >= 0)
                                sceIoWrite(writing_file, decom_buffer, out_sz);
                        } while(comp_stream.avail_out == 0);
                        offset += available;
                        UpdateProgress(args[2]);
                        if(vpk_left_bytes == 0) {
                            if(writing_file >= 0)
                                sceIoClose(writing_file);
                            inflateEnd(&comp_stream);
                            vpk_buffer_status = 0;
                            vpk_left_bytes = 2;
                        }
                        break;
                    }
                }
            }
            free(buffer);
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

// static void send_to_client(short pkt_type, char* data, short data_length) {
//     static pkt_header hdr;
//     hdr.length = 4 + data_length;
//     hdr.type = pkt_type;
//     sceNetSend(client_sockfd, &hdr, 4, 0);
//     if(data && data_length > 0)
//         sceNetSend(client_sockfd, data, data_length, 0);
// }

static void send_response(short pkt_type, int narg, int result1, int result2) {
    static pkt_response resp;
    resp.length = 4 + narg * 4;
    resp.type = pkt_type;
    resp.result1 = result1;
    resp.result2 = result2;
    sceNetSend(client_sockfd, &resp, resp.length, 0);
}

static void handle_packet(short pkt_type, char* data, short data_length) {
    static int current_offset = 0;

    switch(pkt_type) {
        case VTP_BEGIN_FILE: {
            // int file_size, int flag, char* file_name
            if(data_length <= 8) {
                send_response(VTPR_BEGIN_FILE, 2, 1, 0); // Invalid request
                break;
            }
            int file_size = 0;
            int file_flag = 0;
            char current_file_name[256];
            memcpy(&file_size, data, 4);
            memcpy(&file_flag, &data[4], 4);
            strncpy(current_file_name, &data[8], 256);
            current_file_name[255] = 0;

            while(dialog_step != DIALOG_STEP_NONE)
                sceKernelDelayThread(1000);
            
            // create dir
            if(create_path(current_file_name) > 0) {
                send_response(VTPR_BEGIN_FILE, 2, 3, 0); // path error
                break;
            }
            // try open file
            SceUID fileid;
            if(current_file_flag & VTP_FLAG_RESTART) {
                fileid = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
                current_offset = 0;
            } else {
                fileid = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
                if(fileid < 0)
                    fileid = sceIoOpen(current_file_name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
                current_offset = sceIoLseek(fileid, 0, SCE_SEEK_END);
            }
            if(fileid < 0) {
                send_response(VTPR_BEGIN_FILE, 2, 4, 0); // cannot open file
                break;
            }
            send_response(VTPR_BEGIN_FILE, 2, 0, current_offset);

            if(!(current_file_flag & VTP_FLAG_NO_PROGRESS)) {
                initMessageDialog(MESSAGE_DIALOG_PROGRESS_BAR, language_container[COPYING]);
                dialog_step = DIALOG_STEP_REMOTE_COPY;
            }
            powerLock();

            task_canceled = 0;
            file_buffer = malloc(FILE_BUFFER_SIZE);
            file_buffer_size = 0;
            add_task(TASK_BEGIN_WRITE_FILE, fileid, file_size, file_flag);
            break;
        }
        case VTP_FILE_CONTENT: {
            if(task_canceled) {
                send_response(VTPR_BEGIN_FILE, 2, 2, 0);
                wait_task_and_clear_status();
                break;
            }
            if(data_length > FILE_BUFFER_SIZE)
                break;
            if(data_length == 0) {
                // send offset
                send_response(VTPR_FILE_CONTINUE, 0, 0, 0);
            } else {
                if(file_buffer_size + data_length > FILE_BUFFER_SIZE) {
                    int taskid = TASK_WRITE_FILE;
                    if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB)
                        taskid = TASK_WRITE_FILE_ZLIB;
                    if(current_file_flag & VTP_FLAG_COMPRESSED_LZMA)
                        taskid = TASK_WRITE_FILE_LZMA;
                    add_task(taskid, (int)file_buffer, file_buffer_size, current_offset);
                    file_buffer = malloc(FILE_BUFFER_SIZE);
                    file_buffer_size = 0;
                }
                memcpy(&file_buffer[file_buffer_size], data, data_length);
                file_buffer_size += data_length;
                current_offset += data_length;
            }
            break;
        }
        case VTP_FILE_END: {
            send_response(VTPR_FILE_END, 0, 0, 0);
            if(file_buffer_size > 0) {
                int taskid = TASK_WRITE_FILE;
                if(current_file_flag & VTP_FLAG_COMPRESSED_ZLIB)
                    taskid = TASK_WRITE_FILE_ZLIB;
                if(current_file_flag & VTP_FLAG_COMPRESSED_LZMA)
                    taskid = TASK_WRITE_FILE_LZMA;
                add_task(taskid, (int)file_buffer, file_buffer_size, current_offset);
                file_buffer = NULL;
                file_buffer_size = 0;
            } else {
                free(file_buffer);
                file_buffer = NULL;
                file_buffer_size = 0;
            }
            add_task(TASK_CLOSE_FILE, 0, 0, 0);
            if(!(current_file_flag & VTP_FLAG_NO_PROGRESS)) {
                sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, 100);
                sceKernelDelayThread(COUNTUP_WAIT);
                closeWaitDialog();
            }
            powerUnlock();
            need_refresh = 1;
            break;
        }
        case VTP_INSTALL_VPK: {
            // int64 all_size
            // int flag
            if(data_length < 12)
                break;
            if(vpk_status > 0) {
                send_response(VTPR_INSTALL_VPK, 1, 1, 0); // VTP_INSTALL_VPK_END should be send before a new vpk
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
                send_response(VTPR_INSTALL_VPK, 1, 2, 0); // user canceled
                break;
            } else {
                vpk_status = 1;
                removePath(PACKAGE_PARENT, NULL);
	            sceIoMkdir(PACKAGE_PARENT, 0777);
                send_response(VTPR_INSTALL_VPK, 1, 0, 0);
                initMessageDialog(MESSAGE_DIALOG_PROGRESS_BAR, language_container[INSTALLING]);
                dialog_step = DIALOG_STEP_REMOTE_COPY;
                file_buffer = malloc(FILE_BUFFER_SIZE);
                file_buffer_size = 0;
                powerLock();
            }
            break;
        }
        case VTP_VPK_CONTENT: {
            if(data_length > FILE_BUFFER_SIZE)
                break;
            if(data_length == 0) {
                send_response(VTPR_VPK_CONTINUE, 0, 0, 0);
            } else {
                if(file_buffer_size + data_length > FILE_BUFFER_SIZE) {
                    add_task(TASK_VPK_BUFFER, (int)file_buffer, file_buffer_size, 0);
                    file_buffer = malloc(FILE_BUFFER_SIZE);
                    file_buffer_size = 0;
                }
                memcpy(&file_buffer[file_buffer_size], data, data_length);
                file_buffer_size += data_length;
            }
            break;
        }
        case VTP_INSTALL_VPK_END: {
            if(vpk_status == 0)
                break;
            if(file_buffer_size) {
                add_task(TASK_VPK_BUFFER, (int)file_buffer, file_buffer_size, 0);
                file_buffer = NULL;
                file_buffer_size = 0;
            }
            wait_task_and_close_file();
            vpk_status = 0;
            if (makeHeadBin() < 0) {
                send_response(VTPR_INSTALL_VPK_END, 1, 1, 0);
                closeWaitDialog();
                errorDialog(-1);
                break;
            }
            if (promote(PACKAGE_DIR) < 0) {
                send_response(VTPR_INSTALL_VPK_END, 1, 2, 0);
                closeWaitDialog();
                errorDialog(-1);
                break;
            }
            send_response(VTPR_INSTALL_VPK_END, 1, 0, 0);
            sceMsgDialogProgressBarSetValue(SCE_MSG_DIALOG_PROGRESSBAR_TARGET_BAR_DEFAULT, 100);
            sceKernelDelayThread(COUNTUP_WAIT);
            closeWaitDialog();
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

    server_started = 1;
    char* recv_buffer = malloc(RECV_BUFFER_SIZE);
    decom_buffer = (unsigned char*)malloc(DECOM_BUFFER_SIZE);
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
    free(decom_buffer);
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
    SceNetCtlInfo info;
    info.ip_address[0] = 0;
    sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
    infoDialog("PSVITA Address:\n%s:%d", info.ip_address, network_port);
}
