import tkinter as tk
from tkinter import messagebox
from SAES import (encrypt, decrypt, encrypt_string, decrypt_string,
                  double_encrypt, double_decrypt, triple_encrypt, triple_decrypt, attack, cbc_encrypt, cbc_decrypt,
                  blocks_to_string,ascii_string_to_blocks,string_to_blocks)


# 选择加密模式
def start_sAES():
    open_main_window("SAES")

def start_double_encryption():
    open_main_window("双重加密")

def start_triple_encryption():
    open_main_window("三重加密")

def start_meeting_in_the_middle():
    open_main_window("中间相遇攻击")

def start_cbc_mode():
    open_main_window("CBC模式")

# 判断是否二进制
def is_binary(s):
    try:
        int(s, 2)
        return True
    except ValueError:
        return False

# 字符串转为二进制
def binary_to_string(binary):
    return ''.join(str(int(bit)) for bit in binary)

# 二进制转为字符串
def string_to_binary(string):
    return ''.join(format(ord(char), '08b') for char in string)

# SAES加密
def encrypt_():
    plain_text = entry_plain.get()
    key = entry_key.get()
    if not plain_text or not key:
        messagebox.showerror("错误", "明文和密钥不能为空")
        return

    if is_binary(plain_text):
        plain_int = int(plain_text,2)
        cipher_int = encrypt(plain_int, int(key,2))
        cipher_text = binary_to_string(format(cipher_int, '016b'))
    else:
        cipher_text = encrypt_string(plain_text, int(key,2))

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, cipher_text)

# SAES解密
def decrypt_():
    cipher_text = entry_plain.get()
    key = entry_key.get()
    if not cipher_text or not key:
        messagebox.showerror("错误", "密文和密钥不能为空")
        return

    if is_binary(cipher_text):
        cipher_int = int(cipher_text, 2)
        plain_int = decrypt(cipher_int, int(key,2))
        plain_text = binary_to_string(format(plain_int, '016b'))
    else:
        plain_text = decrypt_string(cipher_text, int(key,2))

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, plain_text)

# 双重加密
def encrypt_d():
    plain_text = entry_plain.get()
    key = entry_key.get()
    if not plain_text or not key:
        messagebox.showerror("错误", "明文和密钥不能为空")
        return

    if is_binary(plain_text):#如果明文是二进制，转为16进制
        plain_int = int(plain_text,2)
        plain_text = hex(plain_int)
    if is_binary(key):  # 如果密钥是二进制，转为16进制
        key_int = int(key, 2)
        key = hex(key_int)

    cipher_text = double_encrypt(int(plain_text,16), int(key,16))

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, bin(cipher_text)[2:])

# 双重解密
def decrypt_d():
    cipher_text = entry_plain.get()
    key = entry_key.get()
    if not cipher_text or not key:
        messagebox.showerror("错误", "明文和密钥不能为空")
        return

    if is_binary(cipher_text):  # 如果明文是二进制，转为16进制
        plain_int = int(cipher_text, 2)
        cipher_text = hex(plain_int)
    if is_binary(key):  # 如果密钥是二进制，转为16进制
        key_int = int(key, 2)
        key = hex(key_int)

    cipher_text = double_decrypt(int(cipher_text, 16), int(key, 16))

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, hex(cipher_text)[2:])


# 三重加密
def encrypt_t():
    plain_text = entry_plain.get()
    key = entry_key.get()
    if not plain_text or not key:
        messagebox.showerror("错误", "明文和密钥不能为空")
        return

    if is_binary(plain_text):#如果明文是二进制，转为16进制
        plain_int = int(plain_text,2)
        plain_text = hex(plain_int)
    if is_binary(key):  # 如果密钥是二进制，转为16进制
        key_int = int(key, 2)
        key = hex(key_int)

    cipher_text = triple_encrypt(int(plain_text,16), int(key,16))

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, bin(cipher_text)[2:])

# 三重解密
def decrypt_t():
    cipher_text = entry_plain.get()
    key = entry_key.get()
    if not cipher_text or not key:
        messagebox.showerror("错误", "明文和密钥不能为空")
        return

    if is_binary(cipher_text):  # 如果明文是二进制，转为16进制
        plain_int = int(cipher_text, 2)
        cipher_text = hex(plain_int)
    if is_binary(key):  # 如果密钥是二进制，转为16进制
        key_int = int(key, 2)
        key = hex(key_int)

    cipher_text = triple_decrypt(int(cipher_text, 16), int(key, 16))

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, bin(cipher_text)[2:])

# 中间相遇攻击
def attack_():
    plaintexts = entry_plain.get()
    ciphertexts = entry_cipher.get()
    if not plaintexts or not ciphertexts:
        messagebox.showerror("错误", "明文和密文不能为空")
        return

    if is_binary(plaintexts) and is_binary(ciphertexts):
        print("明文:", plaintexts)
        print("密文:", ciphertexts)
        found_keys = attack(plaintexts, ciphertexts)

        print(len(found_keys))

        key_results = ""
        if found_keys:
            for k1, k2 in found_keys:
                key_results += f"找到的密钥: {((k1 << 16) | k2):032b}\n"
        else:
            key_results = "未找到密钥"
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, key_results)
    else:
        messagebox.showerror("错误", "请输入二进制格式的明文和密文")


# CBC模式
# CBC模式加密
def encrypt_CBC():
    plain_text = entry_plain.get()
    key = entry_key.get()
    iv = entry_iv.get()  # 获取用户输入的IV
    if not plain_text or not key or not iv:
        messagebox.showerror("错误", "明文、密钥和IV不能为空")
        return

    # if is_binary(plain_text):  # 如果明文是二进制，转为16进制
    #     plain_int = int(plain_text, 2)
    #     plain_text = hex(plain_int)
    if is_binary(key):  # 如果密钥是二进制，转为16进制
        key_int = int(key, 2)
        key = hex(key_int)
    if is_binary(iv):  # 如果IV是二进制，转为16进制
        iv_int = int(iv, 2)
        iv = hex(iv_int)

    try:
        cipher_text = cbc_encrypt(plain_text, int(key, 16), int(iv, 16))
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, cipher_text)
    except Exception as e:
        messagebox.showerror("错误", f"加密过程中发生错误: {str(e)}")


# CBC模式解密
def decrypt_CBC():
    cipher_text = entry_plain.get()
    key = entry_key.get()
    iv = entry_iv.get()  # 获取用户输入的IV
    if not cipher_text or not key or not iv:
        messagebox.showerror("错误", "密文、密钥和IV不能为空")
        return


    if is_binary(key):  # 如果密钥是二进制，转为16进制
        key_int = int(key, 2)
        key = hex(key_int)
    if is_binary(iv):  # 如果IV是二进制，转为16进制
        iv_int = int(iv, 2)
        iv = hex(iv_int)

    try:
        plain_text = cbc_decrypt(cipher_text, int(key, 16), int(iv, 16))
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, plain_text)
    except Exception as e:
        messagebox.showerror("错误", f"解密过程中发生错误: {str(e)}")

# 打开二级窗口
def open_main_window(mode):
    global main_window, entry_plain, entry_key, text_output,entry_cipher,entry_iv
    main_window = tk.Toplevel()
    main_window.title(mode + " - 加密/解密工具")

    if mode=='SAES':
        label_plain = tk.Label(main_window, text="明文/密文:")
        label_plain.pack()

        entry_plain = tk.Entry(main_window, width=50)
        entry_plain.pack()

        label_key = tk.Label(main_window, text="密钥:")
        label_key.pack()

        entry_key = tk.Entry(main_window, width=50)
        entry_key.pack()

        label_output = tk.Label(main_window, text="输出结果:")
        label_output.pack()

        text_output = tk.Text(main_window, height=10, width=50)
        text_output.pack()

        button_encrypt = tk.Button(main_window, text="加密", command=encrypt_)
        button_encrypt.pack()

        button_decrypt = tk.Button(main_window, text="解密", command=decrypt_)
        button_decrypt.pack()


    if mode == '双重加密':
        label_plain = tk.Label(main_window, text="明文/密文:")
        label_plain.pack()

        entry_plain = tk.Entry(main_window, width=50)
        entry_plain.pack()

        label_key = tk.Label(main_window, text="密钥:")
        label_key.pack()

        entry_key = tk.Entry(main_window, width=50)
        entry_key.pack()

        label_output = tk.Label(main_window, text="输出结果:")
        label_output.pack()

        text_output = tk.Text(main_window, height=10, width=50)
        text_output.pack()

        button_encrypt = tk.Button(main_window, text="加密", command=encrypt_d)
        button_encrypt.pack()

        button_decrypt = tk.Button(main_window, text="解密", command=decrypt_d)
        button_decrypt.pack()

    if mode=='三重加密':
        label_plain = tk.Label(main_window, text="明文/密文:")
        label_plain.pack()

        entry_plain = tk.Entry(main_window, width=50)
        entry_plain.pack()

        label_key = tk.Label(main_window, text="密钥:")
        label_key.pack()

        entry_key = tk.Entry(main_window, width=50)
        entry_key.pack()

        label_output = tk.Label(main_window, text="输出结果:")
        label_output.pack()

        text_output = tk.Text(main_window, height=10, width=50)
        text_output.pack()

        button_encrypt = tk.Button(main_window, text="加密", command=encrypt_t)
        button_encrypt.pack()

        button_decrypt = tk.Button(main_window, text="解密", command=decrypt_t)
        button_decrypt.pack()

    if mode == '中间相遇攻击':
        label_plain = tk.Label(main_window, text="明文:")
        label_plain.pack()

        entry_plain = tk.Entry(main_window, width=50)
        entry_plain.pack()

        label_cipher = tk.Label(main_window, text="密文:")
        label_cipher.pack()

        entry_cipher = tk.Entry(main_window, width=50)
        entry_cipher.pack()

        label_output = tk.Label(main_window, text="可能的密钥:")
        label_output.pack()

        text_output = tk.Text(main_window, height=10, width=50)
        text_output.pack()

        button_encrypt = tk.Button(main_window, text="攻击", command=attack_)
        button_encrypt.pack()

    if mode == 'CBC模式':
        label_plain = tk.Label(main_window, text="明文/密文:")
        label_plain.pack()

        entry_plain = tk.Entry(main_window, width=50)
        entry_plain.pack()

        label_key = tk.Label(main_window, text="密钥:")
        label_key.pack()

        entry_key = tk.Entry(main_window, width=50)
        entry_key.pack()

        label_iv = tk.Label(main_window, text="初始化向量IV:")
        label_iv.pack()

        entry_iv = tk.Entry(main_window, width=50)
        entry_iv.pack()

        label_output = tk.Label(main_window, text="输出结果:")
        label_output.pack()

        text_output = tk.Text(main_window, height=10, width=50)
        text_output.pack()

        button_encrypt = tk.Button(main_window, text="加密", command=encrypt_CBC)
        button_encrypt.pack()

        button_decrypt = tk.Button(main_window, text="解密", command=decrypt_CBC)
        button_decrypt.pack()





# 创建选择界面的主窗口
root = tk.Tk()
root.title("选择加密模式")

button_sAES = tk.Button(root, text="SAES", command=start_sAES)
button_sAES.pack()

button_double_encryption = tk.Button(root, text="双重加密", command=start_double_encryption)
button_double_encryption.pack()

button_triple_encryption = tk.Button(root, text="三重加密", command=start_triple_encryption)
button_triple_encryption.pack()

button_meeting_in_the_middle = tk.Button(root, text="中间相遇攻击", command=start_meeting_in_the_middle)
button_meeting_in_the_middle.pack()

button_cbc_mode = tk.Button(root, text="CBC模式", command=start_cbc_mode)
button_cbc_mode.pack()

button_quit = tk.Button(root, text="退出", command=root.quit)
button_quit.pack()

root.mainloop()