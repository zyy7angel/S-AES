# S-AES
Implementation and exploration of S-AES encryption algorithm
***
## 第一关：基本测试
主要使用函数`encrypt()`和`decrypt()`实现    
    
    # 基础加密函数
    def encrypt(plain: int, key: int) -> int:
        # 密钥扩展
        key = key_expansion(key)

        # 明文转为状态矩阵
        state = int_to_matrix(plain)

        # 进行加密过程
        state = key_addition(state, key[:2])  # 初始密钥加
        state = substitute_nibble(state)  # 半字节代替
        state = shift_rows(state)  # 行移位
        state = mix_columns(state)  # 列混淆
        state = key_addition(state, key[2:4])  # 第二轮密钥加

        state = substitute_nibble(state)  # 半字节代替
        state = shift_rows(state)  # 行移位
        state = key_addition(state, key[4:])  # 最后一轮密钥加

        # 返回加密后的结果
        return matrix_to_int(state)

    # 基础解密函数
    def decrypt(cipher: int, key: int) -> int:
        # 密钥扩展
        key = key_expansion(key)

        # 密文转为状态矩阵
        state = int_to_matrix(cipher)

        # 解密过程
        state = key_addition(state, key[4:])  # 初始密钥加
        state = shift_rows(state)  # 行移位
        state = substitute_nibble(state, inverse=True)  # 半字节代替
        state = key_addition(state, key[2:4])  # 第二轮密钥加
        state = mix_columns(state, inverse=True)  # 列混淆

        state = shift_rows(state)  # 行移位
        state = substitute_nibble(state, inverse=True)  # 半字节代替
        state = key_addition(state, key[:2])  # 最后一轮密钥加

        # 返回解密后的结果
        return matrix_to_int(state)

1. 加密    
   明文：`1010011101001001`,    
   密钥：`0010110101010101`;    
   密文：`1100001101001001`.        
   ![](/images/S-AES-encrypt.jpg)        
2. 解密    
   密文：`1100001101001001`;    
   密钥：`0010110101010101`;    
   明文：`1010011101001001`.    
   ![](/images/S-AES-decrypt.jpg)    
   ***
## 第二关：交叉测试
要求：考虑到是"算法标准"，所有人在编写程序的时候需要使用相同算法流程和转换单元(替换盒、列混淆矩阵等)，以保证算法和程序在异构的系统或平台上都可以正常运行。设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P。     
我们与古渲宇组做交叉测试     
* 加密    
   明文：`1010101010101010`;    
   密钥：`0101010101010101`;    
   密文：`0110010001101011`.    
   古渲宇组：    
   ![](https://imgur.la/images/2024/10/30/image751d1b4d14cfdf9e.png)    
   我们组：    
   ![](/images/cross-encrypt.jpg)    
***
## 第三关：扩展功能
扩展要求：考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为2 Bytes)，对应地输出也可以是ACII字符串(很可能是乱码)。         
主要通过四个扩展功能实现：    
`ascii_string_to_blocks()`    
`blocks_to_ascii_string()`    
`string_to_blocks()`    
`blocks_to_string()`    
1. ascii加密        
   明文：`Hello,World!`    
   密钥：`0010110101010101`    
   密文：`éVÍ^]bGíL¶È'M`    
   ![](/images/ascii-encrypt.jpg)        
2. ascii解密        
   密文：`éVÍ^]bGíL¶È'M`    
   密钥：`0010110101010101`        
   明文：`Hello,World!`               
   ![](/images/ascii-decrypt.jpg)            
***
## 第四关： 多重加密
1. 双重加密
   要求：将S-AES算法通过双重加密进行扩展，分组长度仍然是16 bits，但密钥长度为32 bits。
   主要实现函数：    
   `double_encrypt()`        
   `double_decrypt()`    
   * 双重加密        
     明文：`0xffff`            
     密钥：`0xffff0000`                
     密文：`11010011100`    
     ![](/images/double-encrypt.jpg)        
   * 双重解密        
     密文：`11010011100`                
     密钥：`0xffff0000`                
     明文：`0xffff`    
     ![](/images/double-decrypt.jpg)        
2. 中间相遇攻击    
   要求：假设你找到了使用相同密钥的明、密文对(一个或多个)，请尝试使用中间相遇攻击的方法找到正确的密钥Key(K1+K2)。            
   解决办法：`attack()`函数实现。传统的暴力破解通常需要尝试每一个可能的密钥组合（假设每个密钥的长度是n位，那么需要2^n次尝试）。通过中间相遇攻击，攻击者可以将问题拆分为两部分：每一部分的暴力搜索都只需要 $2^\\frac{n}{2}$次尝试。因此，整体时间复杂度降低到O($2^\\frac{n}{2}$)，即暴力破解的搜索空间减半。        
   明密文对：    
   `1111111111111111`
   `0000011010011100`        
   找到的密钥：        
   ![](/images/attack.jpg)    
3. 三重加密    
   要求：将S-AES算法通过三重加密进行扩展，下面两种模式选择一种完成：    
   __(1)按照32 bits密钥Key(K1+K2)的模式进行三重加密解密,__        
   (2)使用48bits(K1+K2+K3)的模式进行三重加解密。    
   选择要求(1),实现函数`triple_encrypt()`
   `triple_decrypt()`        
   * 三重加密    
     明文：`1100110011001100`            
     密钥：`0xaaaaaaaa`                
     密文：`110100010110101`    
     ![](/images/three-encrypt.jpg)    
   * 三重解密    
     密文：`110100010110101`                
     密钥：`0xaaaaaaaa`                 
     明文：`1100110011001100`    
     ![](/images/three-decrypt.jpg)    
***
## 第五关：工作模式
要求：基于S-AES算法，使用密码分组链(CBC)模式对较长的明文消息进行加密。注意初始向量(16 bits) 的生成，并需要加解密双方共享。         
在CBC模式下进行加密，并尝试对密文分组进行替换或修改，然后进行解密，请对比篡改密文前后的解密结果。  
核心代码：    
    
    # Cipher Block Chaining (CBC) 加密
    def cbc_encrypt(plain: str, key: int, iv: int) -> str:
        plain = string_to_blocks(plain)
        cipher = []
        prev_cipher = iv
        for plain_block in plain:
            cipher_block = encrypt(plain_block ^ prev_cipher, key)
            cipher.append(cipher_block)
            prev_cipher = cipher_block
        return blocks_to_string(cipher)


    # Cipher Block Chaining (CBC) 解密
    def cbc_decrypt(cipher: str, key: int, iv: int) -> str: #->：返回str类型
        cipher = string_to_blocks(cipher)
        plain = []
        prev_cipher = iv
        for cipher_block in cipher:
            plain_block = decrypt(cipher_block, key) ^ prev_cipher
            plain.append(plain_block)
            prev_cipher = cipher_block
        return blocks_to_string(plain)      

1. CBC加密    
   明文：`10000000000011110001110110111111`            
   密钥：`0x2d55`        
   初始向量：`0x1234`           
   密文：`11100101011011010000100010000111`        
   ![](/images/CBC-encrypt.jpg)            
3. CBC解密        
   密文：`11100101011011010000100010000111`            
   密钥：`0x2d55`          
   初始向量：`0x1234`              
   明文：`10000000000011110001110110111111`                
   ![](/images/CBC-decrypt.jpg)               






















   
