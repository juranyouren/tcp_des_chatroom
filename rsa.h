#ifndef RSA_H
#define RSA_H

#include <cstdint>
#include <vector>
#include <random>
#include <tuple>

class RSA {
public:
    struct PublicKey { 
        uint64_t e, n; 
    };
    
    struct PrivateKey { 
        uint64_t d, n; 
    };
    
    RSA() : rng(std::random_device{}()) {}
    
    void GenerateKeys(int bits=16) {
        p = GeneratePrime(bits);
        q = GeneratePrime(bits);
        n = p * q;
        phi = (p-1) * (q-1);
        e = ChooseExponent();
        d = ModInverse(e, phi);
    }

    PublicKey GetPublicKey() const { return {e, n}; }
    PrivateKey GetPrivateKey() const { return {d, n}; }

    static uint64_t Encrypt(uint64_t m, PublicKey pub) {
        return PowMod(m, pub.e, pub.n);
    }

    static uint64_t Decrypt(uint64_t c, PrivateKey priv) {
        return PowMod(c, priv.d, priv.n);
    }

private:
    uint64_t p, q, n, phi, e, d;
    std::mt19937_64 rng;

    // 快速幂取模
    static uint64_t PowMod(uint64_t base, uint64_t exp, uint64_t mod) {
        uint64_t result = 1;
        base %= mod;
        while (exp > 0) {
            if (exp & 1)
                result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

    // 生成指定位数的素数
    uint64_t GeneratePrime(int bits) {
        std::uniform_int_distribution<uint64_t> dist(1ULL << (bits-1), (1ULL << bits) - 1);
        while (true) {
            uint64_t p = dist(rng) | 1;  // 确保是奇数
            if (IsPrime(p)) return p;
        }
    }

    // Miller-Rabin素性测试
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

    // 计算最大公约数
    static uint64_t gcd(uint64_t a, uint64_t b) {
        while (b != 0) {
            uint64_t t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    // 选择与phi互质的指数e
    uint64_t ChooseExponent() {
        // 常用65537作为公钥指数
        if (phi > 65537 && gcd(65537, phi) == 1) 
            return 65537;
            
        // 从3开始寻找与phi互质的奇数
        for (uint64_t e = 3; e < phi; e += 2) {
            if (gcd(e, phi) == 1) return e;
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