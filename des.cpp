#include "des.h"

// 构造函数
CDesOperate::CDesOperate() {
    // 初始化子密钥数组
    memset(m_arrOutKey, 0, sizeof(m_arrOutKey));
}

// 析构函数
CDesOperate::~CDesOperate() {
    // 清空子密钥数组，防止密钥泄露
    memset(m_arrOutKey, 0, sizeof(m_arrOutKey));
}

// 生成初始密钥
void CDesOperate::MakeFirstKey(const char* key, int key_len) {
    // 确保密钥长度至少为8字节
    if (key_len < 8) {
        return;
    }
    
    // 将密钥转换为64位整数
    unsigned int left = 0, right = 0;
    for (int i = 0; i < 4; i++) {
        left = (left << 8) | (unsigned char)key[i];
        right = (right << 8) | (unsigned char)key[i + 4];
    }
    
    // 应用PC1置换，生成56位密钥
    unsigned int newLeft = 0, newRight = 0;
    for (int i = 0; i < 28; i++) {
        int index = PC1_Table[i] - 1;
        if (index < 32) {
            newLeft |= ((left >> (31 - index)) & 0x01) << (27 - i);
        } else {
            newLeft |= ((right >> (63 - index)) & 0x01) << (27 - i);
        }
    }
    
    for (int i = 28; i < 56; i++) {
        int index = PC1_Table[i] - 1;
        if (index < 32) {
            newRight |= ((left >> (31 - index)) & 0x01) << (55 - i);
        } else {
            newRight |= ((right >> (63 - index)) & 0x01) << (55 - i);
        }
    }
    
    // 存储初始子密钥
    m_arrOutKey[0][0] = newLeft;
    m_arrOutKey[0][1] = newRight;
}

// 生成16轮子密钥
void CDesOperate::MakeKey() {
    // 根据初始子密钥生成16轮子密钥
    for (int i = 1; i < 16; i++) {
        // 循环左移
        unsigned int left = m_arrOutKey[i-1][0];
        unsigned int right = m_arrOutKey[i-1][1];
        
        // 根据LOOP_Table确定左移位数
        int loop = LOOP_Table[i];
        
        // 执行循环左移
        left = ((left << loop) | (left >> (28 - loop))) & 0x0FFFFFFF;
        right = ((right << loop) | (right >> (28 - loop))) & 0x0FFFFFFF;
        
        m_arrOutKey[i][0] = left;
        m_arrOutKey[i][1] = right;
    }
    
    // 应用PC2置换，生成48位子密钥
    for (int i = 0; i < 16; i++) {
        unsigned int left = m_arrOutKey[i][0];
        unsigned int right = m_arrOutKey[i][1];
        unsigned int newLeft = 0, newRight = 0;
        
        // 应用PC2置换
        for (int j = 0; j < 24; j++) {
            int index = PC2_Table[j] - 1;
            if (index < 28) {
                newLeft |= ((left >> (27 - index)) & 0x01) << (23 - j);
            } else {
                newLeft |= ((right >> (55 - index)) & 0x01) << (23 - j);
            }
        }
        
        for (int j = 24; j < 48; j++) {
            int index = PC2_Table[j] - 1;
            if (index < 28) {
                newRight |= ((left >> (27 - index)) & 0x01) << (47 - j);
            } else {
                newRight |= ((right >> (55 - index)) & 0x01) << (47 - j);
            }
        }
        
        m_arrOutKey[i][0] = newLeft;
        m_arrOutKey[i][1] = newRight;
    }
}

// DES算法的F函数
unsigned int CDesOperate::F(unsigned int r, unsigned int k0, unsigned int k1) {
    // 扩展置换E，将32位扩展为48位
    unsigned int expandR = 0;
    for (int i = 0; i < 48; i++) {
        int index = E_Table[i] - 1;
        expandR |= ((r >> (31 - index)) & 0x01) << (47 - i);
    }
    
    // 与子密钥异或
    expandR = ((expandR >> 24) ^ k0) << 24 | (expandR & 0x00FFFFFF) ^ k1;
    
    // S盒替换，将48位压缩为32位
    unsigned int output = 0;
    for (int i = 0; i < 8; i++) {
        // 获取当前6位
        unsigned char sixBits = (expandR >> (42 - i * 6)) & 0x3F;
        
        // 计算S盒的行和列
        unsigned char row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
        unsigned char col = (sixBits >> 1) & 0x0F;
        
        // S盒替换
        unsigned char val = S_Box[i][row][col];
        
        // 合并结果
        output |= val << (28 - i * 4);
    }
    
    // P置换
    unsigned int result = 0;
    for (int i = 0; i < 32; i++) {
        int index = P_Table[i] - 1;
        result |= ((output >> (31 - index)) & 0x01) << (31 - i);
    }
    
    return result;
}

// 加密单个64位块
void CDesOperate::EncryBlock(unsigned int& left, unsigned int& right) {
    // 初始置换IP
    unsigned int newLeft = 0, newRight = 0;
    unsigned int oldLeft = left, oldRight = right;
    
    for (int i = 0; i < 32; i++) {
        int index = IP_Table[i] - 1;
        if (index < 32) {
            newLeft |= ((oldLeft >> (31 - index)) & 0x01) << (31 - i);
        } else {
            newLeft |= ((oldRight >> (63 - index)) & 0x01) << (31 - i);
        }
    }
    
    for (int i = 32; i < 64; i++) {
        int index = IP_Table[i] - 1;
        if (index < 32) {
            newRight |= ((oldLeft >> (31 - index)) & 0x01) << (63 - i);
        } else {
            newRight |= ((oldRight >> (63 - index)) & 0x01) << (63 - i);
        }
    }
    
    left = newLeft;
    right = newRight;
    
    // 16轮Feistel网络
    for (int i = 0; i < 16; i++) {
        unsigned int temp = right;
        right = left ^ F(right, m_arrOutKey[i][0], m_arrOutKey[i][1]);
        left = temp;
    }
    
    // 交换左右两部分
    unsigned int temp = left;
    left = right;
    right = temp;
    
    // 逆初始置换IP^-1
    newLeft = 0;
    newRight = 0;
    oldLeft = left;
    oldRight = right;
    
    for (int i = 0; i < 32; i++) {
        int index = IPR_Table[i] - 1;
        if (index < 32) {
            newLeft |= ((oldLeft >> (31 - index)) & 0x01) << (31 - i);
        } else {
            newLeft |= ((oldRight >> (63 - index)) & 0x01) << (31 - i);
        }
    }
    
    for (int i = 32; i < 64; i++) {
        int index = IPR_Table[i] - 1;
        if (index < 32) {
            newRight |= ((oldLeft >> (31 - index)) & 0x01) << (63 - i);
        } else {
            newRight |= ((oldRight >> (63 - index)) & 0x01) << (63 - i);
        }
    }
    
    left = newLeft;
    right = newRight;
}

// 解密单个64位块
void CDesOperate::DecryBlock(unsigned int& left, unsigned int& right) {
    // 初始置换IP
    unsigned int newLeft = 0, newRight = 0;
    unsigned int oldLeft = left, oldRight = right;
    
    for (int i = 0; i < 32; i++) {
        int index = IP_Table[i] - 1;
        if (index < 32) {
            newLeft |= ((oldLeft >> (31 - index)) & 0x01) << (31 - i);
        } else {
            newLeft |= ((oldRight >> (63 - index)) & 0x01) << (31 - i);
        }
    }
    
    for (int i = 32; i < 64; i++) {
        int index = IP_Table[i] - 1;
        if (index < 32) {
            newRight |= ((oldLeft >> (31 - index)) & 0x01) << (63 - i);
        } else {
            newRight |= ((oldRight >> (63 - index)) & 0x01) << (63 - i);
        }
    }
    
    left = newLeft;
    right = newRight;
    
    // 16轮Feistel网络，注意子密钥顺序与加密相反
    for (int i = 15; i >= 0; i--) {
        unsigned int temp = right;
        right = left ^ F(right, m_arrOutKey[i][0], m_arrOutKey[i][1]);
        left = temp;
    }
    
    // 交换左右两部分
    unsigned int temp = left;
    left = right;
    right = temp;
    
    // 逆初始置换IP^-1
    newLeft = 0;
    newRight = 0;
    oldLeft = left;
    oldRight = right;
    
    for (int i = 0; i < 32; i++) {
        int index = IPR_Table[i] - 1;
        if (index < 32) {
            newLeft |= ((oldLeft >> (31 - index)) & 0x01) << (31 - i);
        } else {
            newLeft |= ((oldRight >> (63 - index)) & 0x01) << (31 - i);
        }
    }
    
    for (int i = 32; i < 64; i++) {
        int index = IPR_Table[i] - 1;
        if (index < 32) {
            newRight |= ((oldLeft >> (31 - index)) & 0x01) << (63 - i);
        } else {
            newRight |= ((oldRight >> (63 - index)) & 0x01) << (63 - i);
        }
    }
    
    left = newLeft;
    right = newRight;
}

// 加密函数
bool CDesOperate::Encry(const char* plaintext, int plaintext_len, char* ciphertext, int& ciphertext_len, const char* key, int key_len) {
    if (plaintext == NULL || ciphertext == NULL || key == NULL) {
        return false;
    }
    
    // 生成子密钥
    MakeFirstKey(key, key_len);
    MakeKey();
    
    // 计算需要的缓冲区大小
    int blockCount = (plaintext_len + 7) / 8; // 向上取整到8字节的倍数
    int bufferSize = blockCount * 8;
    
    if (ciphertext_len < bufferSize) {
        return false; // 输出缓冲区不足
    }
    
    // 设置实际输出长度
    ciphertext_len = bufferSize;
    
    // 按8字节(64位)分组加密
    for (int i = 0; i < blockCount; i++) {
        unsigned int left = 0, right = 0;
        
        // 将明文转换为64位整数
        for (int j = 0; j < 4; j++) {
            if (i * 8 + j < plaintext_len) {
                left = (left << 8) | (unsigned char)plaintext[i * 8 + j];
            } else {
                left = left << 8; // 不足部分补0
            }
            
            if (i * 8 + j + 4 < plaintext_len) {
                right = (right << 8) | (unsigned char)plaintext[i * 8 + j + 4];
            } else {
                right = right << 8; // 不足部分补0
            }
        }
        
        // 加密单个块
        EncryBlock(left, right);
        
        // 将加密结果写入输出缓冲区
        for (int j = 0; j < 4; j++) {
            ciphertext[i * 8 + j] = (left >> (24 - j * 8)) & 0xFF;
            ciphertext[i * 8 + j + 4] = (right >> (24 - j * 8)) & 0xFF;
        }
    }
    
    return true;
}

// 解密函数
bool CDesOperate::Decry(const char* ciphertext, int ciphertext_len, char* plaintext, int& plaintext_len, const char* key, int key_len) {
    if (ciphertext == NULL || plaintext == NULL || key == NULL) {
        return false;
    }
    
    // 密文长度必须是8的倍数
    if (ciphertext_len % 8 != 0) {
        return false;
    }
    
    // 生成子密钥
    MakeFirstKey(key, key_len);
    MakeKey();
    
    // 检查输出缓冲区大小
    if (plaintext_len < ciphertext_len) {
        return false; // 输出缓冲区不足
    }
    
    // 设置实际输出长度
    plaintext_len = ciphertext_len;
    
    // 按8字节(64位)分组解密
    int blockCount = ciphertext_len / 8;
    for (int i = 0; i < blockCount; i++) {
        unsigned int left = 0, right = 0;
        
        // 将密文转换为64位整数
        for (int j = 0; j < 4; j++) {
            left = (left << 8) | (unsigned char)ciphertext[i * 8 + j];
            right = (right << 8) | (unsigned char)ciphertext[i * 8 + j + 4];
        }
        
        // 解密单个块
        DecryBlock(left, right);
        
        // 将解密结果写入输出缓冲区
        for (int j = 0; j < 4; j++) {
            plaintext[i * 8 + j] = (left >> (24 - j * 8)) & 0xFF;
            plaintext[i * 8 + j + 4] = (right >> (24 - j * 8)) & 0xFF;
        }
    }
    
    return true;
}