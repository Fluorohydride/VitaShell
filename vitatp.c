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

#define NET_BUFFER_SIZE 1*1024*1024 // 1mb
#define FILE_BUFFER_SIZE 2*1024*1024

static short server_started = 0;
static void* net_buffer = NULL;
static char* file_buffer[2];
static int file_buffer_size[2];
static int current_file_buffer = 0;
static short buffer_handling = 0;
static short buffer_lock = 0;

static SceNetInAddr vita_addr;
static SceUID server_thid = 0;

static int netctl_init = -1;
static int net_init = -1;
static char network_ip[16];
static short network_port;
static int server_sockfd;

static void handle_packet(short data_length, short pkt_type, char* data) {
    if(file_buffer_size[current_file_buffer] + data_length > FILE_BUFFER_SIZE) {
        buffer_lock = 1;
        while(buffer_handling > 0);
        current_file_buffer = 1 - current_file_buffer;
        file_buffer_size[current_file_buffer] = 0;
        buffer_lock = 0;
    }
    int idx = current_file_buffer;
    memcpy(&file_buffer[idx][file_buffer_size[idx]], data, data_length);
    file_buffer_size[idx] += data_length;
}

static int server_thread(SceSize args, void *argp) {
    int ret;

    SceNetSockaddrIn serveraddr;

    /* Create server socket */
    server_sockfd = sceNetSocket("network socket", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);

    /* Fill the server's address */
    serveraddr.sin_family = SCE_NET_AF_INET;
    serveraddr.sin_addr.s_addr = sceNetHtonl(SCE_NET_INADDR_ANY);
    serveraddr.sin_port = sceNetHtons(network_port);

    /* Bind the server's address to the socket */
    ret = sceNetBind(server_sockfd, (SceNetSockaddr *)&serveraddr, sizeof(serveraddr));

    /* Start listening */
    ret = sceNetListen(server_sockfd, 128);

    file_buffer[0] = malloc(FILE_BUFFER_SIZE);
    file_buffer[1] = malloc(FILE_BUFFER_SIZE);
    file_buffer_size[0] = 0;
    file_buffer_size[1] = 0;
    current_file_buffer = 0;
    while (1) {
        /* Accept clients */
        SceNetSockaddrIn clientaddr;
        int client_sockfd;
        unsigned int addrlen = sizeof(clientaddr);

        client_sockfd = sceNetAccept(server_sockfd, (SceNetSockaddr *)&clientaddr, &addrlen);
        if (client_sockfd >= 0) {
            /* Get the client's IP address */
            char remote_ip[16];
            char recv_buffer[4096];
            int recv_offset = 0;
            short packet_length = 0;
            short packet_type = 0;            
            sceNetInetNtop(SCE_NET_AF_INET, &clientaddr.sin_addr.s_addr, remote_ip, sizeof(remote_ip));
            // begin recv
            while (1) {
                int recv_size = sceNetRecv(client_sockfd, &recv_buffer[recv_offset], 4096 - recv_offset, 0);
                if (recv_size > 0) {
                    recv_offset += recv_size;
                    /* Wait 1 ms before sending any data */
                    // sceKernelDelayThread(1*1000);
                    int offset = 0;
                    while(offset + 4 <= recv_offset) {
                        int left_data_size = recv_offset - offset;
                        memcpy(&packet_length, &recv_buffer[offset], 2);
                        if(packet_length < 4) {
                            // packet length error, skip
                            offset += 2;
                            continue;
                        };
                        if(packet_length > left_data_size) {
                            //need receive more data
                            memmove(recv_buffer, &recv_buffer[offset], left_data_size);
                            recv_offset = left_data_size;
                            break;
                        }
                        memcpy(&packet_type, &recv_buffer[offset + 2], 2);
                        handle_packet(packet_length - 4, packet_type, &recv_buffer[offset + 4]);
                        offset += packet_length;
                    }
                } else if (recv_size == 0) {
                    /* Value 0 means connection closed by the remote peer */
                    break;
                } else if (recv_size == SCE_NET_ERROR_EINTR) {
                    /* Socket aborted (ftpvita_fini() called) */
                    break;
                } else {
                    /* Other errors */
                    break;
                }
            }
            /* Close the client's socket */
            sceNetSocketClose(client_sockfd);
        } else {
            break;
        }
    }
    sceKernelExitDeleteThread(0);
    return 0;
}

int vitatp_begin_server(char *vita_ip, short port) {
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
    network_port = port;

    /* Save the IP of PSVita to a global variable */
    sceNetInetPton(SCE_NET_AF_INET, info.ip_address, &vita_addr);

    /* Create server thread */
    server_thid = sceKernelCreateThread("server_thread",
        server_thread, 0x10000100, 0x10000, 0, 0, NULL);

    /* Start the server thread */
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

    free(file_buffer[0]);
    free(file_buffer[1]);
    file_buffer_size[0] = 0;
    file_buffer_size[1] = 0;
    current_file_buffer = 0;

    netctl_init = -1;
    net_init = -1;
    net_buffer = NULL;
    server_started = 0;
    return 0;
}
