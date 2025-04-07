#include "tcp_socket.h"

// 密钥定义
#define KEY "benbemmi"  // 8字节密钥
#define KEY_LEN 8

int main() {
    char choice;
    CTcpSocket socket;
    
    // 用户选择运行模式
    printf("Client or Server?\n");
    scanf("%c", &choice);
    getchar(); // 消耗换行符
    
    if (choice == 's' || choice == 'S') {
        // 服务器模式
        if (!socket.InitServer()) {
            fprintf(stderr, "Failed to initialize server\n");
            return 1;
        }
        
        if (!socket.StartListen()) {
            fprintf(stderr, "Failed to start listening\n");
            return 1;
        }
        
        // 接受客户端连接
        if (socket.AcceptConnection() < 0) {
            fprintf(stderr, "Failed to accept connection\n");
            return 1;
        }
        
        // 开始加密聊天
        socket.SecretChat(KEY, KEY_LEN);
    } else if (choice == 'c' || choice == 'C') {
        // 客户端模式
        char server_ip[64];
        
        // 获取服务器IP地址
        printf("Please input the server address:\n");
        if (fgets(server_ip, sizeof(server_ip), stdin) == NULL) {
            fprintf(stderr, "Failed to read server address\n");
            return 1;
        }
        
        // 去除换行符
        int len = strlen(server_ip);
        if (server_ip[len - 1] == '\n') {
            server_ip[len - 1] = '\0';
        }
        
        // 连接到服务器
        if (!socket.ConnectToServer(server_ip)) {
            fprintf(stderr, "Failed to connect to server\n");
            return 1;
        }
        
        // 开始加密聊天
        socket.SecretChat(KEY, KEY_LEN);
    } else {
        fprintf(stderr, "Invalid choice. Please enter 's' for server or 'c' for client.\n");
        return 1;
    }
    
    return 0;
}