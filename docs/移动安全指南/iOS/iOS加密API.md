# iOS 加密 API[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#ios-cryptographic-apis)

在[“移动应用密码学”](https://mas.owasp.org/MASTG/General/0x04g-Testing-Cryptography/)一章中，我们介绍了一般密码学最佳实践，并描述了密码学使用不当时可能出现的典型问题。在本章中，我们将更详细地介绍 iOS 的加密 API。我们将展示如何识别源代码中这些 API 的使用以及如何解释加密配置。在审查代码时，确保将使用的加密参数与本指南中链接的当前最佳实践进行比较。

## 验证密码标准算法的配置（MSTG-CRYPTO-2 和 MSTG-CRYPTO-3）[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#verifying-the-configuration-of-cryptographic-standard-algorithms-mstg-crypto-2-and-mstg-crypto-3)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#overview)

Apple 提供的库包括最常见的加密算法的实现。[Apple 的加密服务指南](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html)是一个很好的参考。它包含有关如何使用标准库初始化和使用加密原语的通用文档，这些信息对源代码分析很有用。

#### 加密套件[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#cryptokit)

Apple CryptoKit 随 iOS 13 一起发布，它建立在 Apple 的原生加密库 corecrypto 之上，该库已通过[FIPS 140-2 验证](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3856)。Swift 框架提供了强类型的 API 接口，有有效的内存管理，符合 equatable，支持泛型。CryptoKit 包含用于散列、对称密钥加密和公钥加密的安全算法。该框架还可以利用 Secure Enclave 中基于硬件的密钥管理器。

Apple CryptoKit 包含以下算法：

**哈希：**

- MD5（不安全模块）
- SHA1（不安全模块）
- SHA-2 256 位摘要
- SHA-2 384 位摘要
- SHA-2 512 位摘要

**对称密钥：**

- 消息验证代码 (HMAC)
- 认证加密
- AES-GCM
- ChaCha20-Poly1305

**公钥：**

- 密钥协议
- 曲线25519
- NIST P-256
- NIST P-384
- NIST P-512

例子：

生成和发布对称密钥：

```
let encryptionKey = SymmetricKey(size: .bits256)
```

计算 SHA-2 512 位摘要：

```
let rawString = "OWASP MTSG"
let rawData = Data(rawString.utf8)
let hash = SHA512.hash(data: rawData) // Compute the digest
let textHash = String(describing: hash)
print(textHash) // Print hash text
```

有关 Apple CryptoKit 的更多信息，请访问以下资源：

- [苹果加密套件 | Apple 开发者文档](https://developer.apple.com/documentation/cryptokit)
- [执行常见的密码操作 | Apple 开发者文档](https://developer.apple.com/documentation/cryptokit/performing_common_cryptographic_operations)
- [WWDC 2019 session 709 | 密码学和您的应用程序](https://developer.apple.com/videos/play/wwdc19/709/)
- [如何计算 String 或 Data 实例的 SHA 散列 | 使用 Swift 进行黑客攻击](https://www.hackingwithswift.com/example-code/cryptokit/how-to-calculate-the-sha-hash-of-a-string-or-data-instance)

#### CommonCrypto、SecKey 和 Wrapper 库[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#commoncrypto-seckey-and-wrapper-libraries)

最常用于加密操作的类是 CommonCrypto，它包含在 iOS Runtime(运行时)中。[通过查看头文件](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html)的源代码，可以最好地剖析 CommonCrypto 对象提供的功能：

- `Commoncryptor.h`给出了对称加密操作的参数。
- `CommonDigest.h`给出了散列算法的参数。
- `CommonHMAC.h`给出了支持的 HMAC 操作的参数。
- `CommonKeyDerivation.h`给出支持的 KDF 函数的参数。
- `CommonSymmetricKeywrap.h`给出了用于使用密钥加密密钥包装对称密钥的函数。

不幸的是，CommonCryptor 在其公共 API 中缺少一些类型的操作，例如：GCM 模式仅在其私有 API 中可用，请参阅[其源代码](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h)。为此，需要一个额外的绑定标头或可以使用其他包装器库。

接下来，对于非对称操作，Apple 提供了[SecKey](https://developer.apple.com/documentation/security/seckey)。[Apple 在其开发者文档](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption)中提供了关于如何使用它的很好的指南。

如前所述：为了提供便利，两者都存在一些包装库。例如，使用的典型库是：

- [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto)
- [海姆达尔](https://github.com/henrinormak/Heimdall)
- [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA)
- [RNC加密器](https://github.com/RNCryptor/RNCryptor)
- [奥术](https://github.com/onmyway133/Arcane)

#### 第三方库[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#third-party-libraries)

有各种可用的第三方库，例如：

- **CJOSE**：随着 JWE 的兴起，以及缺乏对 AES GCM 的公共支持，其他库已经找到了自己的出路，例如[CJOSE](https://github.com/cisco/cjose)。CJOSE 仍然需要更高级别的包装，因为它们只提供 C/C++ 实现。
- **CryptoSwift**：Swift 中的一个库，可以在[GitHub 上找到](https://github.com/krzyzanowskim/CryptoSwift)。该库支持各种散列函数、MAC 函数、CRC 函数、对称密码和基于密码的密钥派生函数。它不是包装器，而是每个密码的完全自行实现的版本。验证功能的有效实现很重要。
- **OpenSSL**：[OpenSSL](https://www.openssl.org/)是用于 TLS 的工具包库，用 C 语言编写。它的大部分加密函数可用于执行各种必要的加密操作，例如创建 (H)MAC、签名、对称和非对称密码、散列等.. 有各种包装器，例如[OpenSSL](https://github.com/ZewoGraveyard/OpenSSL)和[MIHCrypto](https://github.com/hohl/MIHCrypto)。
- **LibSodium**：Sodium 是一个现代的、易于使用的软件库，用于加密、解密、签名、密码散列等。它是 NaCl 的可移植、可交叉编译、可安装、可打包的分支，具有兼容的 API 和可进一步提高可用性的扩展 API。有关详细信息，请参阅[LibSodiums 文档](https://download.libsodium.org/doc/installation)。有一些包装器库，例如[Swift-sodium](https://github.com/jedisct1/swift-sodium)、[NAChloride](https://github.com/gabriel/NAChloride)和[libsodium-ios](https://github.com/mochtu/libsodium-ios)。
- **Tink**：谷歌的一个新的密码学库。[谷歌在其安全博客上](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html)解释了其背后的库的原因。可以在[Tinks GitHub 存储库](https://github.com/google/tink)中找到源代码。
- **Themis**：一个用于 Swift、Obj-C、Android/Java、C++、JS、Python、Ruby、PHP、Go 的存储和消息传递的加密库。[Themis](https://github.com/cossacklabs/themis)使用 LibreSSL/OpenSSL 引擎 libcrypto 作为依赖项。它支持 Objective-C 和 Swift 用于密钥生成、安全消息传递（例如有效负载加密和签名）、安全存储和设置安全会话。有关详细信息，请参阅[他们的 wiki 。](https://github.com/cossacklabs/themis/wiki/Objective-C-Howto)
- **其他**：还有许多其他库，例如[CocoaSecurity](https://github.com/kelp404/CocoaSecurity)、[Objective-C-RSA](https://github.com/ideawu/Objective-C-RSA)和[aerogear-ios-crypto](https://github.com/aerogear/aerogear-ios-crypto)。其中一些不再维护，可能从未经过安全审查。与往常一样，建议寻找受支持和维护的库。
- **DIY**：越来越多的开发人员创建了他们自己的密码或加密函数实现。这种做法是*非常*不鼓励的，如果使用，应该由密码学专家进行非常彻底的审查。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#static-analysis)

在 节中已经讨论了很多关于弃用算法和密码配置的内容`Cryptography for Mobile Apps`。显然，应该为本章中提到的每个库验证这些。注意如何删除密钥保存数据结构和纯文本数据结构的定义。如果使用关键字`let`，那么您将创建一个难以从内存中擦除的不可变结构。确保它是可以很容易地从内存中删除的父结构的一部分（例如`struct`，暂时存在的）。

#### 通用密码器[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#commoncryptor)

如果应用程序使用 Apple 提供的标准加密实现，确定相关算法状态的最简单方法是检查对函数的调用`CommonCryptor`，例如`CCCrypt`和`CCCryptorCreate`。[源代码](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h)包含 CommonCryptor.h 所有函数的签名。例如，`CCCryptorCreate`具有以下签名：

```
CCCryptorStatus CCCryptorCreate(
    CCOperation op,             /* kCCEncrypt, etc. */
    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
    const void *key,            /* raw key material */
    size_t keyLength,
    const void *iv,             /* optional initialization vector */
    CCCryptorRef *cryptorRef);  /* RETURNED */
```

然后，您可以比较所有`enum`类型以确定使用了哪种算法、填充和密钥材料。注意密钥材料：密钥应该安全地生成——使用密钥派生函数或随机数生成函数。请注意，在“移动应用程序的加密技术”一章中已弃用的功能仍然以编程方式受支持。不应使用它们。

#### 第三方库[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#third-party-libraries_1)

鉴于所有第三方库的不断发展，这不应该是在静态分析方面评估每个库的地方。还是有一些注意点：

- **查找正在使用的库**：这可以使用以下方法完成：
- 如果使用 Carthage，请检查[cartfile 。](https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile)
- 如果使用 Cocoapods，请检查[podfile](https://guides.cocoapods.org/syntax/podfile.html)。
- 检查链接库：打开 xcodeproj 文件并检查项目属性。转到**Build Phases**选项卡并检查任何库的**Link Binary With Libraries**中的条目。请参阅前面有关如何使用[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)获取类似信息的部分。
- 在复制粘贴源的情况下：搜索头文件（在使用 Objective-C 的情况下），否则搜索已知库的已知方法名称的 Swift 文件。
- **确定正在使用的版本**：始终检查正在使用的库的版本，并检查是否有可用的新版本修补了可能的漏洞或缺点。即使没有更新版本的库，也可能尚未审查加密功能。因此，我们始终建议使用经过验证的库，或者确保您有能力、知识和经验自行进行验证。
- **用手？**：我们建议不要推出自己的加密货币，也不要自己实施已知的加密函数。

## 测试密钥管理（MSTG-CRYPTO-1 和 MSTG-CRYPTO-5）[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#testing-key-management-mstg-crypto-1-and-mstg-crypto-5)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#overview_1)

关于如何在设备上存储密钥，有多种方法。根本不存储密钥将确保不会转储任何密钥材料。这可以通过使用密码密钥派生函数（例如 PKBDF-2）来实现。请参见下面的示例：

```
func pbkdf2SHA1(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA256(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    let passwordData = password.data(using: String.Encoding.utf8)!
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)
    let derivedKeyDataLength = derivedKeyData.count
    let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        salt.withUnsafeBytes { saltBytes in

            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, passwordData.count,
                saltBytes, salt.count,
                hash,
                UInt32(rounds),
                derivedKeyBytes, derivedKeyDataLength
            )
        }
    }
    if derivationStatus != 0 {
        // Error
        return nil
    }

    return derivedKeyData
}

func testKeyDerivation() {
    let password = "password"
    let salt = Data([0x73, 0x61, 0x6C, 0x74, 0x44, 0x61, 0x74, 0x61])
    let keyByteCount = 16
    let rounds = 100_000

    let derivedKey = pbkdf2SHA1(password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}
```

- *来源：[https](https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios)`Arcane` ://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios，在库的测试套件中测试*

当需要存储密钥时，建议使用Keychain，只要选择的保护等级不是`kSecAttrAccessibleAlways`. 将密钥存储在任何其他位置，例如`NSUserDefaults`、属性列表文件或来自 Core Data 或 Realm 的任何其他接收器，通常不如使用 KeyChain 安全。即使使用`NSFileProtectionComplete`数据保护类保护 Core Data 或 Realm 的同步，我们仍然建议使用 KeyChain。[有关详细信息，请参阅“ iOS 上](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/)的数据存储”一章。

KeyChain 支持两种类型的存储机制：密钥要么由存储在安全飞地中的加密密钥保护，要么密钥本身在安全飞地内。后者仅在您使用 ECDH 签名密钥时成立。有关其实现的更多详细信息，请参阅[Apple 文档](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)。

最后三个选项包括在源代码中使用硬编码加密密钥，具有基于稳定属性的可预测密钥派生函数，以及将生成的密钥存储在与其他应用程序共享的位置。使用硬编码加密密钥显然不是可行的方法，因为这意味着应用程序的每个实例都使用相同的加密密钥。攻击者只需执行一次工作即可从源代码中提取密钥（无论是存储在Native还是在 Objective-C/Swift 中）。因此，攻击者可以解密应用程序加密的任何其他数据。接下来，当您具有基于标识符的可预测密钥派生函数时，其他应用程序可以访问该函数，攻击者只需找到 KDF 并将其应用于设备即可找到密钥。最后，

当涉及到密码学时，你不应该忘记另外两个概念：

1. 始终使用公钥加密/验证并始终使用私钥解密/签名。
2. 切勿将密钥（对）重复用于其他目的：这可能会泄露有关密钥的信息：使用单独的密钥对进行签名和单独的密钥（对）进行加密。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#static-analysis_1)

有各种关键字可供查找：检查“验证密码标准算法的配置”部分的概述和静态分析中提到的库，对于哪些关键字，您可以最好地检查密钥的存储方式。

始终确保：

- 如果用于保护高风险数据，密钥不会在设备上同步。
- 密钥不会在没有额外保护的情况下存储。
- 键没有硬编码。
- 密钥不是从设备的稳定功能派生的。
- 使用低级语言（例如 C/C++）不会隐藏密钥。
- 密钥不会从不安全的位置导入。

大多数静态分析的建议已经可以在“测试 iOS 的数据存储”一章中找到。接下来，您可以在以下页面阅读它：

- [Apple 开发者文档：证书和密钥](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys)
- [Apple 开发者文档：生成新密钥](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys)
- [Apple 开发者文档：密钥生成属性](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes)

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#dynamic-analysis)

Hook加密方法并分析正在使用的密钥。在执行加密操作时监控文件系统访问，以评估密钥材料写入或读取的位置。

## 测试随机数生成 (MSTG-CRYPTO-6)[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#testing-random-number-generation-mstg-crypto-6)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#overview_2)

Apple 提供了一个[随机化服务](https://developer.apple.com/reference/security/randomization_services)API，它可以生成加密安全的随机数。

随机化服务 API 使用该`SecRandomCopyBytes`函数生成数字。这是`/dev/random`设备文件的包装函数，它提供从 0 到 255 的加密安全伪随机值。确保所有随机数都是使用此 API 生成的。开发人员没有理由使用不同的。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#static-analysis_2)

在 Swift 中，[`SecRandomCopyBytes`API](https://developer.apple.com/reference/security/1399291-secrandomcopybytes)定义如下：

```
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

[Objective-C](https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc)版本是

```
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

以下是 API 用法的示例：

```
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

注意：如果其他机制用于代码中的随机数，请验证这些机制是否是上述 API 的包装器或检查它们的安全随机性。通常这太难了，这意味着您最好坚持上面的实现。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#dynamic-analysis_1)

如果你想测试随机性，你可以尝试捕获大量数字并使用[Burp 的 sequencer 插件](https://portswigger.net/burp/documentation/desktop/tools/sequencer)检查随机性的质量有多好。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#references)

### OWASP MASVS[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#owasp-masvs)

- MSTG-CRYPTO-1：“该应用程序不依赖使用硬编码密钥的对称加密作为唯一的加密方法。”
- MSTG-CRYPTO-2：“该应用程序使用经过验证的加密原语实现。”
- MSTG-CRYPTO-3：“该应用程序使用适合特定用例的加密原语，并配置了符合行业最佳实践的参数。”
- MSTG-CRYPTO-5：“该应用程序不会出于多种目的重复使用相同的加密密钥。”
- MSTG-CRYPTO-6：“所有随机值都是使用足够安全的随机数生成器生成的。”

### 一般安全文件[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#general-security-documentation)

- Apple 开发者安全文档 - https://developer.apple.com/documentation/security
- Apple 安全指南 - https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf

### 加密算法的配置[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#configuration-of-cryptographic-algorithms)

- Apple 的加密服务指南 - https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html
- 关于随机化 SecKey 的 Apple 开发者文档 - https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html
- 关于 Secure Enclave 的 Apple 文档 - https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave?language=objc
- 头文件的源代码 - https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html
- CommonCrypto 中的 GCM - https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h
- 关于 SecKey 的 Apple 开发者文档 - https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html
- IDZSwiftCommonCrypto - https://github.com/iosdevzone/IDZSwiftCommonCrypto
- 海姆达尔 - https://github.com/henrinormak/Heimdall
- SwiftyRSA - https://github.com/TakeScoop/SwiftyRSA
- RNCryptor - https://github.com/RNCryptor/RNCryptor
- 奥术 - https://github.com/onmyway133/Arcane
- CJOSE - https://github.com/cisco/cjose
- CryptoSwift - https://github.com/krzyzanowskim/CryptoSwift
- OpenSSL - https://www.openssl.org/
- LibSodiums 文档 - https://download.libsodium.org/doc/installation
- 谷歌 Tink - https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html
- Themis - https://github.com/cossacklabs/themis
- cartfile - https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile
- Podfile - https://guides.cocoapods.org/syntax/podfile.html

### 随机数文档[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#random-number-documentation)

- 关于随机化的 Apple 开发者文档 - https://developer.apple.com/documentation/security/randomization_services
- 关于 secrandomcopybytes 的 Apple 开发者文档 - https://developer.apple.com/reference/security/1399291-secrandomcopybytes
- Burp Suite 定序器 - https://portswigger.net/burp/documentation/desktop/tools/sequencer

### 密钥管理[¶](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/#key-management)

- Apple 开发者文档：证书和密钥 - https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys
- Apple 开发者文档：生成新密钥 - https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys
- Apple 开发者文档：密钥生成属性 - https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes
