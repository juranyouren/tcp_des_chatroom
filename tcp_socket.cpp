#include "tcp_socket.h"

// 构造函数
CTcpSocket::CTcpSocket() {
    m_socket = -1;
    m_client_socket = -1;
    m_is_server = false;
    
    // 初始化地址结构
    memset(&m_server_addr, 0, sizeof(m_server_addr));
    memset(&m_client_addr, 0, sizeof(m_client_addr));

    // 初始化DES密钥
    memset(m_des_key, 0, sizeof(m_des_key));
}

// 析构函数
CTcpSocket::~CTcpSocket() {
    // 关闭套接字
    CloseSocket();
}

// 初始化服务器并完成密钥交换
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

// 启动服务端安全通信，包含RSA密钥交换
bool CTcpSocket::StartSecureServer() {
    // 检查套接字状态
    if (m_client_socket < 0) {
        return false;
    }

    std::cout << "\n[服务端] 开始RSA密钥交换和DES安全通信建立..." << std::endl;
    
    // 生成RSA密钥对
    std::cout << "[服务端] 生成RSA密钥对" << std::endl;
    m_rsa.GenerateKeys();
    
    // 获取公钥
    RSA::PublicKey pub_key = m_rsa.GetPublicKey();
    RSA::PrivateKey priv_key = m_rsa.GetPrivateKey();
    std::cout << "[服务端] 生成的RSA公钥: e=" << pub_key.e << ", n=" << pub_key.n << std::endl;
    std::cout << "[服务端] 生成的RSA私钥: d=" << priv_key.d << ", n=" << priv_key.n << std::endl;
    
    // 发送公钥给客户端
    std::cout << "[服务端] 发送公钥 (e,n) = (" << pub_key.e << "," << pub_key.n << ")" << std::endl;
    if (!SendData((char*)&pub_key, sizeof(pub_key))) {
        perror("发送RSA公钥失败");
        return false;
    }
    std::cout << "[服务端] 已发送RSA公钥给客户端" << std::endl;
    
    // 接收加密后的DES密钥
    uint64_t encrypted_des_key[4];
    int recv_bytes = RecvData((char*)encrypted_des_key, sizeof(encrypted_des_key));
    if (recv_bytes <= 0) {
        perror("接收加密DES密钥失败");
        return false;
    }
    std::cout << "[服务端] 接收加密的DES密钥: " << recv_bytes << " 字节" << std::endl;
    
    std::cout << "[服务端] 加密后的DES密钥块: ";
    for(int i=0; i<4; i++) std::cout << encrypted_des_key[i] << " ";
    std::cout << std::endl;
    
    // 解密DES密钥
    std::cout << "\n[服务端] 使用私钥解密DES密钥..." << std::endl;
    unsigned short* key_parts = (unsigned short*)m_des_key;
    for (int i = 0; i < 4; i++) {
        std::cout << "[服务端] 解密块" << i << ": " 
                  << encrypted_des_key[i] << " -> ";
        
        // 检查是否超出n的范围
        if (encrypted_des_key[i] >= priv_key.n) {
            std::cout << "错误：密文值超出模数n的范围!" << std::endl;
            encrypted_des_key[i] %= priv_key.n;
            std::cout << "已修正为: " << encrypted_des_key[i] << std::endl;
        }
        
        key_parts[i] = (unsigned short)RSA::Decrypt(encrypted_des_key[i], priv_key);
        std::cout << key_parts[i] << std::endl;
    }
    
    // 转换回主机字节序
    for (int i = 0; i < 4; i++) {
        key_parts[i] = ntohs(key_parts[i]);  // 从网络字节序转换回主机字节序
    }
    
    std::cout << "[服务端] DES密钥解密完成 (HEX): ";
    for (int i = 0; i < 8; i++) {
        printf("%02X ", (unsigned char)m_des_key[i]);
    }
    std::cout << std::endl;
    
    // 显示ASCII艺术流程图
    std::cout << "\n===== RSA密钥交换流程 =====" << std::endl;
    std::cout << "+-----------------+       +-----------------+\n"
                 "|   服务端        |       |   客户端        |\n"
                 "| 生成p,q,n,φ,e,d |------>| 接收公钥(e,n)   |\n"
                 "| p=" << m_rsa.GetP() << ", q=" << m_rsa.GetQ() << "    |       | 生成DES密钥     |\n"
                 "| φ(n)=" << m_rsa.GetPhi() << "      |<------| 加密并发送     |\n"
                 "| 使用私钥d解密   |       +-----------------+\n"
                 "+-----------------+\n" << std::endl;
                 
    // 开始加密通信
    return SecretChat(m_des_key, 8);
}

// 连接到服务器并完成密钥交换
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
    
    printf("连接成功！\n");
    
    m_is_server = false;
    m_client_socket = m_socket; // 客户端模式下，client_socket与socket相同
    return true;
}

// 启动客户端安全通信，包含RSA密钥交换
bool CTcpSocket::StartSecureClient() {
    // 检查套接字状态
    if (m_client_socket < 0) {
        return false;
    }
    
    std::cout << "\n[客户端] 开始RSA密钥交换和DES安全通信建立..." << std::endl;
    
    // 接收服务器的RSA公钥
    RSA::PublicKey pub_key;
    int recv_bytes = RecvData((char*)&pub_key, sizeof(pub_key));
    if (recv_bytes <= 0) {
        perror("接收RSA公钥失败");
        return false;
    }
    std::cout << "[客户端] 已接收服务器RSA公钥: e=" << pub_key.e << ", n=" << pub_key.n << std::endl;
    
    // 验证接收到的公钥是否合法
    if (pub_key.e == 0 || pub_key.n == 0) {
        std::cerr << "[客户端] 错误: 接收到的公钥无效!" << std::endl;
        return false;
    }
    
    // 生成随机DES密钥
    GenerateDesKey(m_des_key, 8);
    std::cout << "\n[客户端] 已生成随机DES密钥 (HEX): ";
    for (int i = 0; i < 8; i++) {
        printf("%02X ", (unsigned char)m_des_key[i]);
    }
    std::cout << std::endl;
    
    // 加密DES密钥
    std::cout << "\n[客户端] 使用RSA公钥加密DES密钥..." << std::endl;
    uint64_t encrypted_des_key[4];
    unsigned short* key_parts = (unsigned short*)m_des_key;
    for (int i = 0; i < 4; i++) {
        std::cout << "[客户端] 加密块" << i << ": " 
                  << key_parts[i] << " -> ";
        
        // 确保明文小于模数n
        if (key_parts[i] >= pub_key.n) {
            std::cerr << "警告: 明文值超过模数n，将被截断" << std::endl;
            key_parts[i] %= pub_key.n;
        }
        
        encrypted_des_key[i] = RSA::Encrypt((uint64_t)key_parts[i], pub_key);
        std::cout << encrypted_des_key[i] << std::endl;
    }
    
    // 发送加密后的DES密钥
    if (!SendData((char*)encrypted_des_key, sizeof(encrypted_des_key))) {
        perror("发送加密DES密钥失败");
        return false;
    }
    std::cout << "[客户端] 已发送加密的DES密钥给服务器" << std::endl;
    
    // 显示ASCII艺术流程图
    std::cout << "\n===== RSA密钥交换流程 =====" << std::endl;
    std::cout << "+-----------------+       +-----------------+\n"
                 "|   服务端        |       |   客户端        |\n"
                 "| 生成RSA密钥对   |------>| 接收公钥(e,n)=" << pub_key.e << "," << pub_key.n << "\n"
                 "|                 |       | 生成DES密钥     |\n"
                 "|                 |<------| 使用公钥加密DES |\n"
                 "| 使用私钥d解密   |       | 发送密文        |\n"
                 "+-----------------+       +-----------------+\n" << std::endl;
    
    // 执行边界值验证测试
    std::cout << "\n[客户端] 执行RSA数学边界值验证..." << std::endl;
    // 创建临时RSA对象用于测试
    RSA test_rsa;
    test_rsa.GenerateKeys(8); // 使用较小的素数便于观察
    RSA::TestEdgeCases(test_rsa);
    
    // 测试用例验证
    uint64_t test_plain = 42;
    std::cout << "\n===== RSA完整性验证测试 =====" << std::endl;
    std::cout << "测试明文: " << test_plain << std::endl;
    
    auto test_pub = test_rsa.GetPublicKey();
    uint64_t test_cipher = RSA::Encrypt(test_plain, test_pub);
    uint64_t test_decrypted = RSA::Decrypt(test_cipher, test_rsa.GetPrivateKey());
    
    std::cout << "\n验证结果: " 
              << "原始明文=" << test_plain 
              << " | 解密结果=" << test_decrypted 
              << " | 是否一致: " << (test_plain == test_decrypted) 
              << std::endl;
    
    // 检测基于当前公钥的实际加密测试
    std::cout << "\n[客户端] 执行实际公钥验证测试..." << std::endl;
    uint64_t real_test = 12345;
    if (real_test < pub_key.n) {
        uint64_t real_cipher = RSA::Encrypt(real_test, pub_key);
        std::cout << "测试值: " << real_test << " -> 加密后: " << real_cipher << std::endl;
    } else {
        std::cout << "跳过实际公钥测试: 测试值大于模数" << std::endl;
    }
    
    // 开始加密通信
    return SecretChat(m_des_key, 8);
}

// 生成随机DES密钥
void CTcpSocket::GenerateDesKey(char* key, int key_len) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    // 生成原始8字节密钥
    for (int i = 0; i < key_len; i++) {
        key[i] = dis(gen);
    }
    
    // 转换为网络字节序（大端）
    uint16_t* p = reinterpret_cast<uint16_t*>(key);
    for (int i = 0; i < key_len/2; i++) {
        p[i] = htons(p[i]);  // 转换字节序
    }
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
    
    // 循环接收直到获取所需的数据量
    int total = 0;
    int bytesleft = buffer_size;
    int n;
    
    while (total < buffer_size) {
        n = recv(sockfd, buffer + total, bytesleft, 0);
        if (n <= 0) {
            // 出错或连接关闭
            if (n < 0) perror("recv failed");
            return (total > 0) ? total : n;
        }
        total += n;
        bytesleft -= n;
    }
    
    // 确保字符串结尾有null终止符
    if (total < buffer_size)
        buffer[total] = '\0';
    else
        buffer[buffer_size - 1] = '\0';
    
    return total;
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
    
    // 验证DES密钥是否有效
    std::cout << "\n[安全通信] 验证DES密钥: ";
    bool has_zero_key = true;
    for (int i = 0; i < key_len; i++) {
        printf("%02X ", (unsigned char)key[i]);
        if (key[i] != 0) has_zero_key = false;
    }
    std::cout << std::endl;
    
    if (has_zero_key) {
        std::cerr << "[错误] DES密钥全为零，密钥交换失败!" << std::endl;
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
        char encrypted[BUFFER_SIZE + 4]; // 增加4字节CRC校验
        
        while (1) {
            // 读取用户输入
            if (fgets(input, BUFFER_SIZE, stdin) == NULL) {
                break;
            }
            
            // 去除换行符
            int len = strlen(input);
            if (len > 0 && input[len - 1] == '\n') {
                input[len - 1] = '\0';
                len--;
            }
            
            // 检查是否退出
            if (strcmp(input, "quit") == 0) {
                break;
            }
            
            // 检查输入是否为空
            if (len == 0) {
                printf("[警告] 不发送空消息\n");
                continue;
            }
            
            // 加密消息
            int encrypted_len = BUFFER_SIZE;
            if (!m_des.Encry(input, len, encrypted + 4, encrypted_len, key, key_len)) {
                fprintf(stderr, "[错误] 加密失败\n");
                continue;
            }
            
            // 计算并添加校验和
            uint32_t crc = 0;
            for (int i = 0; i < encrypted_len; i++) {
                crc += (unsigned char)encrypted[i + 4];
            }
            memcpy(encrypted, &crc, 4);
            
            // 显示加密后的内容（十六进制格式）
            printf("[发送] 加密数据 (HEX): CRC=%08X | ", crc);
            for (int i = 0; i < (encrypted_len > 16 ? 16 : encrypted_len); i++) {
                printf("%02X ", (unsigned char)encrypted[i + 4]);
            }
            if (encrypted_len > 16) printf("...");
            printf(" (%d字节)\n", encrypted_len);
            
            // 发送加密消息
            if (!SendData(encrypted, encrypted_len + 4)) {
                fprintf(stderr, "[错误] 发送失败\n");
                break;
            }
        }
        
        // 子进程结束
        exit(0);
    } else {
        // 父进程：负责接收消息
        char buffer[BUFFER_SIZE + 4]; // 增加4字节CRC校验
        char decrypted[BUFFER_SIZE];
        
        // 设置信号处理，防止子进程成为僵尸进程
        signal(SIGCHLD, SIG_IGN);
        
        while (1) {
            // 接收加密消息
            int n = RecvData(buffer, BUFFER_SIZE + 4);
            if (n <= 0) {
                if (n < 0) {
                    perror("[错误] 接收数据失败");
                } else {
                    std::cout << "[通知] 连接已关闭" << std::endl;
                }
                break;
            }
            
            // 检查数据长度 (至少需要4字节CRC + 8字节加密数据)
            if (n <= 12) {
                std::cerr << "[错误] 接收数据长度不足 (" << n << " 字节)" << std::endl;
                continue;
            }
            
            // 提取校验和
            uint32_t received_crc;
            memcpy(&received_crc, buffer, 4);
            
            // 计算校验和
            uint32_t calculated_crc = 0;
            for (int i = 4; i < n; i++) {
                calculated_crc += (unsigned char)buffer[i];
            }
            
            // 验证校验和
            if (received_crc != calculated_crc) {
                std::cerr << "[错误] 校验和不匹配: 预期=" << received_crc << ", 计算=" << calculated_crc << std::endl;
                continue;
            }
            
            // 显示接收到的加密数据
            std::cout << "[接收] 加密数据 (HEX): CRC=" << received_crc << " | ";
            for (int i = 0; i < ((n-4) > 16 ? 16 : (n-4)); i++) {
                printf("%02X ", (unsigned char)buffer[i + 4]);
            }
            if (n-4 > 16) printf("...");
            printf(" (%d字节)\n", n-4);
            
            // 解密消息
            int decrypted_len = BUFFER_SIZE;
            if (!m_des.Decry(buffer + 4, n - 4, decrypted, decrypted_len, key, key_len)) {
                fprintf(stderr, "[错误] 解密失败，可能是密钥不匹配\n");
                
                // 调试信息: 尝试猜测可能的密钥偏移问题
                fprintf(stderr, "[调试] 尝试修复解密:\n");
                char temp_key[8];
                memcpy(temp_key, key, key_len);
                
                // 尝试字节序翻转
                for (int i = 0; i < key_len/2; i++) {
                    char t = temp_key[i];
                    temp_key[i] = temp_key[key_len-1-i];
                    temp_key[key_len-1-i] = t;
                }
                
                if (m_des.Decry(buffer + 4, n - 4, decrypted, decrypted_len, temp_key, key_len)) {
                    fprintf(stderr, "[警告] 字节序翻转后可以解密成功，请检查密钥交换逻辑\n");
                }
                continue;
            }
            
            // 确保解密后的消息以null结尾
            if (decrypted_len < BUFFER_SIZE)
                decrypted[decrypted_len] = '\0';
            else
                decrypted[BUFFER_SIZE - 1] = '\0';
            
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