#include "tcp_socket.h"
#include <ctype.h>

int main() {
    char choice;
    CTcpSocket socket;
    
    // 用户选择运行模式
    printf("选择运行模式 - 服务器(S) 或 客户端(C):\n");
    scanf("%c", &choice);
    getchar(); // 消耗换行符
    
    if (choice == 's' || choice == 'S') {
        // 服务器模式
        printf("启动服务器模式...\n");
        if (!socket.InitServer()) {
            fprintf(stderr, "服务器初始化失败\n");
            return 1;
        }
        
        printf("开始监听客户端连接...\n");
        if (!socket.StartListen()) {
            fprintf(stderr, "启动监听失败\n");
            return 1;
        }
        
        printf("等待客户端连接...\n");
        // 接受客户端连接
        if (socket.AcceptConnection() < 0) {
            fprintf(stderr, "接受连接失败\n");
            return 1;
        }
        
        // 启动安全通信（包含RSA密钥交换）
        printf("开始RSA密钥交换和DES加密通信...\n");
        socket.StartSecureServer();
    } else if (choice == 'c' || choice == 'C') {
        // 客户端模式
        char server_ip[64] = {0};
        
        // 获取服务器IP地址
        printf("请输入服务器IP地址:\n");
        if (fgets(server_ip, sizeof(server_ip), stdin) == NULL) {
            fprintf(stderr, "读取服务器地址失败\n");
            return 1;
        }
        
        // 去除换行符和空白字符
        int len = strlen(server_ip);
        while (len > 0 && (isspace(server_ip[len - 1]) || server_ip[len - 1] == '\n')) {
            server_ip[len - 1] = '\0';
            len--;
        }
        
        // 打印输入的地址用于调试
        printf("正在连接到服务器: '%s'\n", server_ip);
        
        // 检查IP地址是否为空
        if (len == 0) {
            fprintf(stderr, "服务器地址不能为空\n");
            return 1;
        }
        
        // 连接到服务器
        if (!socket.ConnectToServer(server_ip)) {
            fprintf(stderr, "连接服务器失败\n");
            return 1;
        }
        
        // 启动安全通信（包含RSA密钥交换）
        printf("开始RSA密钥交换和DES加密通信...\n");
        socket.StartSecureClient();
    } else {
        fprintf(stderr, "无效选择。请输入'S'表示服务器或'C'表示客户端。\n");
        return 1;
    }
    
    return 0;
}