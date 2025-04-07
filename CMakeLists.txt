# CMakeLists.txt for DES-based TCP Chat Program

# 设置CMake最低版本要求
cmake_minimum_required(VERSION 3.10)

# 设置项目名称
project(DES_TCP_Chat)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编译选项
add_compile_options(-Wall -g)

# 指定源文件
set(SOURCES
    main.cpp
    tcp_socket.cpp
    des.cpp
)

# 创建可执行文件
add_executable(chat ${SOURCES})

# 如果需要链接其他库，可以使用以下命令
# target_link_libraries(chat PRIVATE <library_name>)