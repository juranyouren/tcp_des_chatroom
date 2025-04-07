#include "tcp_socket.h"

// 构造函数
CTcpSocket::CTcpSocket() {
    m_socket = -1;
    m_client_socket = -1;
    m_is_server = false;
    
    // 初始化地址结构
    memset(&m_server_addr, 0, sizeof(m_server_addr));
    memset(&m_client_addr, 0, sizeof(m_client_addr));
}

// 析构函数
CTcpSocket::~CTcpSocket() {
    // 关闭套接字
    CloseSocket();
}

// 初始化服务器
bool CTcpSocket::InitServer(int port) {
    // 创建套接字
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) {
        perror("socket creation failed");
        return false;
    }
    
    // 设置服务器地址
    m_server_addr.sin_family = AF_INET;
    m_server_addr.sin_addr.s_addr = INADDR_ANY;
    m_server_addr.sin_port = htons(port);
    
    // 设置套接字选项，允许地址重用
    int opt = 1;
    if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    // 绑定套接字到指定端口
    if (bind(m_socket, (struct sockaddr*)&m_server_addr, sizeof(m_server_addr)) < 0) {
        perror("bind failed");
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    m_is_server = true;
    return true;
}

// 开始监听
bool CTcpSocket::StartListen() {
    if (m_socket < 0 || !m_is_server) {
        return false;
    }
    
    // 开始监听连接请求
    if (listen(m_socket, MAX_CONN) < 0) {
        perror("listen failed");
        return false;
    }
    
    printf("Listening...\n");
    return true;
}

// 接受连接
int CTcpSocket::AcceptConnection() {
    if (m_socket < 0 || !m_is_server) {
        return -1;
    }
    
    // 接受客户端连接
    socklen_t client_len = sizeof(m_client_addr);
    m_client_socket = accept(m_socket, (struct sockaddr*)&m_client_addr, &client_len);
    
    if (m_client_socket < 0) {
        perror("accept failed");
        return -1;
    }
    
    // 打印客户端信息
    printf("server: got connection from %s, port %d, socket %d\n",
           inet_ntoa(m_client_addr.sin_addr),
           ntohs(m_client_addr.sin_port),
           m_client_socket);
    
    return m_client_socket;
}

// 连接到服务器
bool CTcpSocket::ConnectToServer(const char* server_ip, int port) {
    // 创建套接字
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) {
        perror("socket creation failed");
        return false;
    }
    
    // 设置服务器地址
    m_server_addr.sin_family = AF_INET;
    m_server_addr.sin_port = htons(port);
    
    // 将IP地址从字符串转换为网络地址
    if (inet_pton(AF_INET, server_ip, &m_server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    // 连接到服务器
    if (connect(m_socket, (struct sockaddr*)&m_server_addr, sizeof(m_server_addr)) < 0) {
        perror("Connection Failed");
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    printf("Connect Success!\n");
    printf("Begin to chat...\n");
    
    m_is_server = false;
    m_client_socket = m_socket; // 客户端模式下，client_socket与socket相同
    return true;
}

// 发送数据
bool CTcpSocket::SendData(const char* data, int data_len) {
    int sockfd = m_is_server ? m_client_socket : m_socket;
    
    if (sockfd < 0) {
        return false;
    }
    
    // 发送数据
    int sent = 0;
    while (sent < data_len) {
        int n = send(sockfd, data + sent, data_len - sent, 0);
        if (n < 0) {
            perror("send failed");
            return false;
        }
        sent += n;
    }
    
    return true;
}

// 接收数据
int CTcpSocket::RecvData(char* buffer, int buffer_size) {
    int sockfd = m_is_server ? m_client_socket : m_socket;
    
    if (sockfd < 0) {
        return -1;
    }
    
    // 接收数据
    int n = recv(sockfd, buffer, buffer_size - 1, 0);
    if (n < 0) {
        perror("recv failed");
        return -1;
    } else if (n == 0) {
        // 连接已关闭
        return 0;
    }
    
    // 确保字符串以null结尾
    buffer[n] = '\0';
    return n;
}

// 确保完整接收数据
int CTcpSocket::TotalRecv(int sockfd, char* buffer, int buffer_size) {
    int total = 0;
    int bytesleft = buffer_size;
    int n;
    
    // 循环接收，直到接收完指定大小的数据
    while (total < buffer_size) {
        n = recv(sockfd, buffer + total, bytesleft, 0);
        if (n <= 0) {
            // 出错或连接关闭
            break;
        }
        total += n;
        bytesleft -= n;
    }
    
    return total;
}

// 关闭套接字
void CTcpSocket::CloseSocket() {
    // 关闭客户端套接字
    if (m_client_socket >= 0 && m_client_socket != m_socket) {
        close(m_client_socket);
        m_client_socket = -1;
    }
    
    // 关闭服务器套接字
    if (m_socket >= 0) {
        close(m_socket);
        m_socket = -1;
    }
}

// 加密聊天主函数
bool CTcpSocket::SecretChat(const char* key, int key_len) {
    if (m_client_socket < 0) {
        return false;
    }
    
    // 创建子进程，实现全双工通信
    pid_t pid = fork();
    
    if (pid < 0) {
        // 创建子进程失败
        perror("fork failed");
        return false;
    } else if (pid == 0) {
        // 子进程：负责发送消息
        char input[BUFFER_SIZE];
        char encrypted[BUFFER_SIZE];
        
        while (1) {
            // 读取用户输入
            if (fgets(input, BUFFER_SIZE, stdin) == NULL) {
                break;
            }
            
            // 去除换行符
            int len = strlen(input);
            if (input[len - 1] == '\n') {
                input[len - 1] = '\0';
                len--;
            }
            
            // 检查是否退出
            if (strcmp(input, "quit") == 0) {
                break;
            }
            
            // 加密消息
            int encrypted_len = BUFFER_SIZE;
            if (!m_des.Encry(input, len, encrypted, encrypted_len, key, key_len)) {
                fprintf(stderr, "Encryption failed\n");
                continue;
            }
            
            // 发送加密消息
            if (!SendData(encrypted, encrypted_len)) {
                fprintf(stderr, "Send failed\n");
                break;
            }
        }
        
        // 子进程结束
        exit(0);
    } else {
        // 父进程：负责接收消息
        char buffer[BUFFER_SIZE];
        char decrypted[BUFFER_SIZE];
        
        // 设置信号处理，防止子进程成为僵尸进程
        signal(SIGCHLD, SIG_IGN);
        
        while (1) {
            // 接收加密消息
            int n = RecvData(buffer, BUFFER_SIZE);
            if (n <= 0) {
                // 连接已关闭或出错
                break;
            }
            
            // 解密消息
            int decrypted_len = BUFFER_SIZE;
            if (!m_des.Decry(buffer, n, decrypted, decrypted_len, key, key_len)) {
                fprintf(stderr, "Decryption failed\n");
                continue;
            }
            
            // 确保解密后的消息以null结尾
            decrypted[decrypted_len] = '\0';
            
            // 显示解密后的消息
            const char* peer_addr = m_is_server ? 
                                   inet_ntoa(m_client_addr.sin_addr) : 
                                   inet_ntoa(m_server_addr.sin_addr);
            printf("Receive message form <%s>: %s\n", peer_addr, decrypted);
        }
        
        // 关闭子进程
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }
    
    return true;
}