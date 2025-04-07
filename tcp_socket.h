#ifndef TCP_SOCKET_H
#define TCP_SOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include "des.h"

// 定义常量
#define BUFFER_SIZE 1024  // 缓冲区大小
#define DEFAULT_PORT 8888  // 默认端口号
#define MAX_CONN 5        // 最大连接数

// TCP通信模块类
class CTcpSocket {
public:
    CTcpSocket();
    ~CTcpSocket();

    // 服务器端方法
    bool InitServer(int port = DEFAULT_PORT);  // 初始化服务器
    bool StartListen();                        // 开始监听
    int AcceptConnection();                    // 接受连接

    // 客户端方法
    bool ConnectToServer(const char* server_ip, int port = DEFAULT_PORT);  // 连接到服务器

    // 通用方法
    bool SendData(const char* data, int data_len);  // 发送数据
    int RecvData(char* buffer, int buffer_size);    // 接收数据
    int TotalRecv(int sockfd, char* buffer, int buffer_size);  // 确保完整接收数据
    void CloseSocket();                              // 关闭套接字

    // 加密通信方法
    bool SecretChat(const char* key, int key_len);   // 加密聊天主函数

private:
    int m_socket;                // 套接字描述符
    int m_client_socket;         // 客户端套接字描述符
    struct sockaddr_in m_server_addr;  // 服务器地址
    struct sockaddr_in m_client_addr;  // 客户端地址
    bool m_is_server;            // 是否为服务器
    CDesOperate m_des;           // DES加密对象
};

#endif // TCP_SOCKET_H