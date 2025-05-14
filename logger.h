#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <iostream>
#include <ctime>
#include <mutex>

// 日志级别枚举
enum LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    NONE // 不记录日志
};

class Logger {
public:
    // 获取日志单例实例
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    // 初始化日志系统
    void init(const std::string& filename, LogLevel consoleLevel = INFO, LogLevel fileLevel = DEBUG) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_logFile.open(filename, std::ios::out | std::ios::app);
        m_consoleLevel = consoleLevel;
        m_fileLevel = fileLevel;
        
        if (m_logFile.is_open()) {
            log(INFO, "日志系统启动");
        } else {
            std::cerr << "无法打开日志文件: " << filename << std::endl;
        }
    }

    // 关闭日志
    void close() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_logFile.is_open()) {
            log(INFO, "日志系统关闭");
            m_logFile.close();
        }
    }

    // 记录日志
    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        std::string levelStr;
        switch (level) {
            case DEBUG:   levelStr = "调试"; break;
            case INFO:    levelStr = "信息"; break;
            case WARNING: levelStr = "警告"; break;
            case ERROR:   levelStr = "错误"; break;
            default:      levelStr = "未知"; break;
        }

        std::string timestamp = getCurrentTimestamp();
        std::string formattedMessage = timestamp + " [" + levelStr + "] " + message;
        
        // 写入文件（如果级别满足要求且文件已打开）
        if (level >= m_fileLevel && m_logFile.is_open()) {
            m_logFile << formattedMessage << std::endl;
            m_logFile.flush();
        }
        
        // 输出到控制台（如果级别满足要求）
        if (level >= m_consoleLevel) {
            if (level == ERROR) {
                std::cerr << formattedMessage << std::endl;
            } else {
                std::cout << formattedMessage << std::endl;
            }
        }
    }

    // 辅助方法：记录不同级别的日志
    void debug(const std::string& message) { log(DEBUG, message); }
    void info(const std::string& message) { log(INFO, message); }
    void warning(const std::string& message) { log(WARNING, message); }
    void error(const std::string& message) { log(ERROR, message); }

    // 设置控制台输出级别
    void setConsoleLevel(LogLevel level) { m_consoleLevel = level; }
    
    // 设置文件输出级别
    void setFileLevel(LogLevel level) { m_fileLevel = level; }

private:
    // 私有构造函数（单例模式）
    Logger() : m_consoleLevel(INFO), m_fileLevel(DEBUG) {}
    // 禁止复制和赋值
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    // 获取当前时间戳
    std::string getCurrentTimestamp() {
        time_t now = time(nullptr);
        char buffer[80];
        struct tm timeInfo;
        localtime_r(&now, &timeInfo);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeInfo);
        return buffer;
    }

    std::ofstream m_logFile;   // 日志文件流
    LogLevel m_consoleLevel;   // 控制台日志级别
    LogLevel m_fileLevel;      // 文件日志级别
    std::mutex m_mutex;        // 互斥锁，保证线程安全
};

// 方便使用的宏
#define LOG_INIT(filename, consoleLevel, fileLevel) Logger::getInstance().init(filename, consoleLevel, fileLevel)
#define LOG_DEBUG(message) Logger::getInstance().debug(message)
#define LOG_INFO(message) Logger::getInstance().info(message)
#define LOG_WARNING(message) Logger::getInstance().warning(message)
#define LOG_ERROR(message) Logger::getInstance().error(message)
#define LOG_CLOSE() Logger::getInstance().close()

#endif // LOGGER_H