# TCP DES Chatroom

本项目是一个基于TCP协议的安全聊天程序，集成了DES对称加密和RSA非对称加密密钥交换，适合学习和演示安全通信原理。

## 功能特性
- 基于TCP的客户端/服务器通信
- 支持多客户端连接
- 使用RSA进行密钥交换，安全分发DES密钥
- 使用DES对消息内容加密传输
- 日志记录功能，便于调试和追踪
- 简单命令行界面

## 文件结构
- `main.cpp`         主程序入口
- `tcp_socket.h/cpp` TCP通信与加密逻辑实现
- `des.h/cpp`        DES加密算法实现
- `rsa.h`            RSA加密算法接口
- `logger.h`         日志系统
- `Makefile`         构建脚本

## 编译方法
在Linux环境下，进入项目目录，执行：

```bash
make
```

编译成功后会生成可执行文件。

## 使用方法
### 启动服务器
```bash
./chatroom_server
```

### 启动客户端
```bash
./chatroom_client <服务器IP>
```

## 依赖
- 标准C/C++库
- Linux Socket API

## 注意事项
- 仅用于学习和演示，不建议用于生产环境
- 需保证服务器端口（如8888）未被占用

## 许可证
MIT License

---
如需扩展功能或遇到问题，欢迎提交Issue或PR。
