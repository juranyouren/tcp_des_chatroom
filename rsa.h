#ifndef RSA_H
#define RSA_H

#include <cstdint>
#include <vector>
#include <random>
#include <tuple>
#include <iostream>

class RSA {
public:
    struct PublicKey { 
        uint64_t e, n; 
    };
    
    struct PrivateKey { 
        uint64_t d, n; 
    };
    
    RSA() : rng(std::random_device{}()) {}
    
    // 为验证需要，将IsPrime和gcd设为公有
    static uint64_t gcd(uint64_t a, uint64_t b) {
        while (b != 0) {
            uint64_t t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    bool IsPrime(uint64_t n, int iter=5) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0) return false;

        uint64_t d = n - 1;
        int s = 0;
        while (d % 2 == 0) { d /= 2; s++; }

        for (int i = 0; i < iter; i++) {
            std::uniform_int_distribution<uint64_t> dist(2, n-2);
            uint64_t a = dist(rng);
            uint64_t x = PowMod(a, d, n);
            if (x == 1 || x == n-1) continue;
            
            bool composite = true;
            for (int j = 0; j < s-1; j++) {
                x = (x * x) % n;
                if (x == n-1) {
                    composite = false;
                    break;
                }
            }
            
            if (composite) return false;
        }
        return true;
    }
    
    void GenerateKeys(int bits=16) {
        p = GeneratePrime(bits);
        q = GeneratePrime(bits);
        n = p * q;
        phi = (p-1) * (q-1);
        e = ChooseExponent();
        d = ModInverse(e, phi);
        
        // 添加验证输出
        std::cout << "\n=== RSA密钥生成验证 ===" << std::endl;
        std::cout << "素数 p: " << p << " | 是否素数: " << IsPrime(p) << std::endl;
        std::cout << "素数 q: " << q << " | 是否素数: " << IsPrime(q) << std::endl;
        std::cout << "模数 n: " << n << " (p*q=" << p*q << ")" << std::endl;
        std::cout << "欧拉函数 φ(n): " << phi << " (实际值: " << (p-1)*(q-1) << ")" << std::endl;
        std::cout << "公钥指数 e: " << e << " (与φ(n)互质: " << (gcd(e,phi)==1) << ")" << std::endl;
        std::cout << "私钥指数 d: " << d << std::endl;
        std::cout << "验证 ed ≡1 mod φ(n): " << (e*d % phi) << std::endl;
    }

    PublicKey GetPublicKey() const { return {e, n}; }
    PrivateKey GetPrivateKey() const { return {d, n}; }
    
    // 为验证目的暴露p和q
    uint64_t GetP() const { return p; }
    uint64_t GetQ() const { return q; }
    uint64_t GetPhi() const { return phi; }

    static uint64_t Encrypt(uint64_t m, PublicKey pub) {
        std::cout << "\n=== 加密过程 ===" << std::endl;
        std::cout << "明文 M: " << m << std::endl;
        std::cout << "使用公钥 (e,n): (" << pub.e << "," << pub.n << ")" << std::endl;
        
        uint64_t c = PowMod(m, pub.e, pub.n);
        std::cout << "密文 C = M^e mod n = " 
                << m << "^" << pub.e << " mod " << pub.n 
                << " = " << c << std::endl;
        return c;
    }

    static uint64_t Decrypt(uint64_t c, PrivateKey priv) {
        std::cout << "\n=== 解密过程 ===" << std::endl;
        std::cout << "密文 C: " << c << std::endl;
        std::cout << "使用私钥 (d,n): (" << priv.d << "," << priv.n << ")" << std::endl;
        
        uint64_t m = PowMod(c, priv.d, priv.n);
        std::cout << "明文 M = C^d mod n = " 
                << c << "^" << priv.d << " mod " << priv.n 
                << " = " << m << std::endl;
        return m;
    }
    
    // 添加边界值测试方法
    static void TestEdgeCases(RSA& rsa) {
        auto pub = rsa.GetPublicKey();
        auto priv = rsa.GetPrivateKey();
        
        std::cout << "\n=== 数学特殊值验证 ===" << std::endl;
        
        // 测试0加密
        uint64_t zero = 0;
        auto cipher = RSA::Encrypt(zero, pub);
        auto decrypted = RSA::Decrypt(cipher, priv);
        std::cout << "0加密测试: " << zero << " -> " << cipher << " -> " << decrypted << std::endl;

        // 测试1加密
        uint64_t one = 1;
        cipher = RSA::Encrypt(one, pub);
        decrypted = RSA::Decrypt(cipher, priv);
        std::cout << "1加密测试: " << one << " -> " << cipher << " -> " << decrypted << std::endl;

        // 测试n-1加密
        uint64_t edge = pub.n - 1;
        cipher = RSA::Encrypt(edge, pub);
        decrypted = RSA::Decrypt(cipher, priv);
        std::cout << "n-1加密测试: " << edge << " -> " << cipher << " -> " << decrypted << std::endl;
        
        // 理论验证输出
        std::cout << "\n=== RSA数学原理验证 ===" << std::endl;
        std::cout << "1. 0^e mod n = " << PowMod(0, pub.e, pub.n) << " (应为0)" << std::endl;
        std::cout << "2. 1^e mod n = " << PowMod(1, pub.e, pub.n) << " (应为1)" << std::endl;
        std::cout << "3. (n-1)^e mod n = " << PowMod(pub.n-1, pub.e, pub.n) << " (应为n-1)" << std::endl;
    }

private:
    uint64_t p, q, n, phi, e, d;
    std::mt19937_64 rng;

    // 快速幂取模，修改为安全的大数乘法方式
    static uint64_t PowMod(uint64_t base, uint64_t exp, uint64_t mod) {
        uint64_t result = 1;
        base %= mod;
        while (exp > 0) {
            if (exp & 1)
                result = MulMod(result, base, mod);
            base = MulMod(base, base, mod);
            exp >>= 1;
        }
        return result;
    }
    
    // 安全的大数乘法取模
    static uint64_t MulMod(uint64_t a, uint64_t b, uint64_t mod) {
        uint64_t res = 0;
        a %= mod;
        b %= mod;
        while (b > 0) {
            if (b & 1) 
                res = (res + a) % mod;
            a = (a << 1) % mod;
            b >>= 1;
        }
        return res;
    }

    // 生成指定位数的素数
    uint64_t GeneratePrime(int bits) {
        std::uniform_int_distribution<uint64_t> dist(1ULL << (bits-1), (1ULL << bits) - 1);
        while (true) {
            uint64_t p = dist(rng) | 1;  // 确保是奇数
            if (IsPrime(p)) return p;
        }
    }

    // 选择与phi互质的指数e
    uint64_t ChooseExponent() {
        // 常用65537作为公钥指数
        if (phi > 65537 && gcd(65537, phi) == 1) {
            std::cout << "使用标准公钥指数e=65537" << std::endl;
            return 65537;
        }
            
        // 如果65537不适合，从3开始寻找与phi互质的较小奇数
        std::cout << "需要选择其他公钥指数e..." << std::endl;
        for (uint64_t e = 3; e < phi && e < UINT32_MAX; e += 2) {
            if (gcd(e, phi) == 1) {
                std::cout << "已选择公钥指数e=" << e << std::endl;
                return e;
            }
        }
        return 3; // 默认值
    }

    // 扩展欧几里得求模逆
    static uint64_t ModInverse(uint64_t a, uint64_t m) {
        int64_t old_r = a, r = m;
        int64_t old_s = 1, s = 0;
        int64_t old_t = 0, t = 1;
        
        while (r != 0) {
            int64_t quotient = old_r / r;
            std::tie(old_r, r) = std::make_tuple(r, old_r - quotient * r);
            std::tie(old_s, s) = std::make_tuple(s, old_s - quotient * s);
            std::tie(old_t, t) = std::make_tuple(t, old_t - quotient * t);
        }
        
        if (old_r > 1) return 0; // 不存在模逆
        if (old_s < 0) old_s += m;
        return old_s;
    }
};

#endif // RSA_H