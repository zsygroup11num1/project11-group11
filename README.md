# project11-group11
在代码中，RFC 6979方法主要应用于SM2签名算法中的确定性随机数k的生成。RFC 6979指定了一种用于确定性签名（deterministic signatures）的方法，目的是在相同的私钥和消息条件下，每次生成的签名都是相同的，从而避免了潜在的安全隐患，如私钥泄漏等。

代码中deterministic_k函数就是应用RFC 6979方法来计算确定性的随机数k的地方。让我们分析代码中该函数的实现：
def deterministic_k(private_key, message):
    # 计算消息的SHA-256哈希值
    h = hashlib.sha256(message).digest()

    # 初始化辅助参数v和k为固定值
    v = b'\x01' * 32
    k = b'\x00' * 32

    # 计算输入消息msg为哈希值h与私钥的组合
    msg = h + private_key.to_bytes(32, 'big')

    # 使用HMAC-SHA256算法迭代计算k
    k = hmac.new(k, msg, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, msg + v, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    # 将计算结果转换为整数，并对SM2曲线的阶n取模，得到最终的随机数k
    return int.from_bytes(hmac.new(k, v, hashlib.sha256).digest(), byteorder='big') % n
代码中首先计算消息的SHA-256哈希值，然后初始化辅助参数v和k为固定值。接下来，将消息哈希值h与私钥组合为输入消息msg，并使用HMAC-SHA256算法迭代计算k和v。最后，将计算得到的结果转换为整数，并对SM2曲线的阶n取模，得到最终的随机数k。

在SM2签名过程中，我们通过调用deterministic_k函数来生成确定性的随机数k，然后使用该随机数k进行签名操作，确保在相同的私钥和消息条件下，每次生成的签名都是相同的。

这样，我们就在代码中应用了RFC 6979方法，使得SM2签名算法具备了确定性签名的特性，提高了签名的可预测性和安全性。请注意，为了保证实际应用的安全性和正确性，建议使用经过验证的密码库来实现RFC 6979和SM2算法。

运行结果：<img width="565" alt="f854b0cba117ce7a86855c75f9e4672" src="https://github.com/zsygroup11num1/project11-group11/assets/129477117/81e8d090-487e-46b9-8151-5d099ddd418e">
