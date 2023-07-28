import os
import hashlib
import hmac
# SM2参数
p = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
a = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC
b = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
n = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
Gx = 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7
Gy = 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0

# 曲线点的加法
def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] == p2[1]:
        lam = (3 * p1[0] * p1[0] + a) * pow(2 * p1[1], -1, p) % p
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    y3 = (lam * (p1[0] - x3) - p1[1]) % p
    return x3, y3

# 曲线点的倍乘
def point_mul(k, point):
    result = None
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k //= 2
    return result

# 生成密钥对
def generate_keypair():
    private_key = int.from_bytes(os.urandom(32), 'big') % n
    public_key = point_mul(private_key, (Gx, Gy))
    return private_key, public_key


# RFC 6979中的deterministic k算法
def deterministic_k(private_key, message):
    h = hashlib.sha256(message).digest()
    v = b'\x01' * 32
    k = b'\x00' * 32
    msg = h + private_key.to_bytes(32, 'big')
    k = hmac.new(k, msg, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, msg + v, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    return int.from_bytes(hmac.new(k, v, hashlib.sha256).digest(), byteorder='big') % n


# 签名
def sign(private_key, message):
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    k = deterministic_k(private_key, message)  # 使用RFC 6979方法来确定k
    r, y = point_mul(k, (Gx, Gy))
    s = (z + r * private_key) * pow(k, -1, n) % n
    return r, s

# 验证签名
def verify(public_key, message, signature):
    r, s = signature
    if not 0 < r < n or not 0 < s < n:
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    w = pow(s, -1, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    x, y = point_add(point_mul(u1, (Gx, Gy)), point_mul(u2, public_key))
    return r == x

# 示例用法
if __name__ == "__main__":
    # 生成密钥对
    private_key, public_key = generate_keypair()

    # 待签名的消息
    message = b"Hello, SM2!"

    # 签名
    signature = sign(private_key, message)

    # 验证签名
    is_valid = verify(public_key, message, signature)
    print("Signature is valid:", is_valid)
