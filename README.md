# MailClientApp

这是一个基于Java的邮件客户端应用，支持构造和发送符合MIME格式的邮件，并实现了S/MIME邮件签名、加密、解密和验证功能。项目依赖 Jakarta Mail 和 BouncyCastle 库，使用 VSCode 创建和管理，配合 PowerShell 脚本 `build.ps1` 进行编译和打包。

## 功能特性

- 构造和发送符合MIME格式的邮件  
- 支持S/MIME邮件签名与验证  
- 支持S/MIME邮件加密与解密  
- 自动识别邮件中的签名和加密结构  
- 解析多层MIME结构，支持复杂邮件内容处理  
- 证书管理与验证（证书链完整性、用途检查、有效期校验、CRL吊销状态等）

## 技术栈

- Java 8及以上  
- Jakarta Mail API  
- BouncyCastle 加密库  
- VSCode 作为开发环境  
- PowerShell 脚本 `build.ps1` 用于编译和打包

## 快速开始

1. 克隆项目代码

    ```bash
    git clone https://github.com/ysy20021208/MailClientApp.git
    cd MailClientApp
    ```

2. 打开 VSCode 并加载项目文件夹

3. 运行项目根目录下的 `build.ps1` 脚本进行编译和打包

    ```powershell
    .\build.ps1
    ```

4. **注意：目前项目仅支持测试邮件地址 `user@z.eshark.cc`，请使用该地址进行测试。**

5. 根据项目说明配置邮件服务器（SMTP/IMAP）参数及证书路径

6. 运行生成的 Jar 文件，执行邮件相关操作（发送、签名、验证、加密、解密）

## 项目结构

```
MailClientApp/
├── .vscode/                  # VSCode 配置目录（如调试配置、工作区设置）
├── BIND9.17.12.x64/          # BIND9 DNS 服务器相关文件（用于 SMIMEA 记录获取）
├── OpenSSL-Win64/            # OpenSSL 相关文件（用于证书处理）
├── bin/                      # 编译输出目录（生成的 .class 文件等）
├── certs/                    # 证书文件目录（用于邮件签名、加密等）
├── lib/                      # 第三方库目录（如 Jakarta Mail、BouncyCastle 等）
├── src/                      # 源代码目录
├── build.ps1                 # PowerShell 构建脚本（用于编译和打包）
├── load_der.py               # Python 脚本（用于加载 CRT 格式证书）
├── load_der copy.py          # Python 脚本（用于加载 CRT 格式证书与 Key 私钥）
├── MailClientApp.jar         # 可执行的 JAR 文件（构建产物）
└── README.md                 # 项目说明文件
```

## 使用说明

- **发送邮件**：目前仅支持向测试邮件地址 `user@z.eshark.cc` 发送邮件。  
- **签名邮件**：加载签名证书和私钥，对邮件进行数字签名。  
- **验证签名**：对接收到的邮件进行签名验证和证书链检查。  
- **加密/解密邮件**：利用证书实现邮件加密和解密功能。

## 依赖库

请确保 `lib` 目录包含以下 jar：

- angus-activation-2.0.1.jar
- bcjmail-jdk18on-1.80.jar
- bcpkix-jdk18on-1.80.jar
- bcprov-jdk18on-1.80.jar
- bcutil-jdk18on-1.80.jar
- jacob.jar
- jakarta.activation-api-2.1.2.jar
- jakarta.mail-2.0.3.jar