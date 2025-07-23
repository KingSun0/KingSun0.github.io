# iOS 数据存储[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#ios-data-storage)

保护身份验证令牌和私人信息等敏感数据是移动安全的关键。在本章中，您将了解用于本地数据存储的 iOS API 以及使用它们的最佳实践。

## 测试本地数据存储（MSTG-STORAGE-1 和 MSTG-STORAGE-2）[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#testing-local-data-storage-mstg-storage-1-and-mstg-storage-2)

应将尽可能少的敏感数据保存在永久本地存储中。然而，在大多数实际场景中，至少必须存储一些用户数据。幸运的是，iOS 提供了安全存储 API，允许开发人员使用每台 iOS 设备上可用的加密硬件。如果正确使用这些 API，敏感数据和文件可以通过硬件支持的 256 位 AES Crypto来保护。

### 数据保护API[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#data-protection-api)

应用程序开发人员可以利用 iOS*数据保护*API 对存储在闪存中的用户数据实施细粒度访问控制。这些 API 建立在随 iPhone 5S 一起引入的 Secure Enclave Processor (SEP) 之上。SEP 是一种协处理器，可为数据保护和密钥管理提供加密操作。设备特定的硬件密钥 - 设备 UID（唯一 ID） - 嵌入在安全区域中，即使在操作系统内核受到威胁时也能确保数据保护的完整性。

数据保护架构基于密钥层次结构。UID 和用户密码密钥（通过 PBKDF2 算法从用户密码导出）位于该层次结构的顶部。它们可以一起用于“解锁”所谓的类密钥，这些密钥与不同的设备状态（例如，设备锁定/解锁）相关联。

存储在 iOS 文件系统上的每个文件都使用其自己的文件密钥加密，该密钥包含在文件元数据中。元数据使用文件系统密钥加密，并使用与应用程序在创建文件时选择的保护类相对应的类密钥进行包装。

下图显示了[iOS 数据保护密钥层次结构](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06d/key_hierarchy_apple.jpg)

文件可以分配给四种不同保护等级中的一种，在[iOS 安全指南](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)中有更详细的解释：

- **完全保护 (NSFileProtectionComplete)**：从用户密码派生的密钥和设备 UID 保护此类密钥。设备锁定后不久，派生密钥就会从内存中擦除，从而使数据在用户解锁设备之前无法访问。
- **Protected Unless Open (NSFileProtectionCompleteUnlessOpen)**：此保护类类似于 Complete Protection，但是，如果文件在解锁时打开，即使用户锁定设备，应用程序也可以继续访问该文件。例如，在后台下载邮件附件时使用此保护等级。
- **Protected Until First User Authentication (NSFileProtectionCompleteUntilFirstUserAuthentication)**：只要用户在启动后第一次解锁设备，就可以访问该文件。即使用户随后锁定设备并且类密钥没有从内存中删除，也可以访问它。
- **无保护 (NSFileProtectionNone)**：此保护类的密钥仅受 UID 保护。类密钥存储在“Effaceable Storage”中，这是 iOS 设备上允许存储少量数据的闪存区域。此保护类存在用于快速远程擦除（立即删除类密钥，这使得数据无法访问）。

除此以外的所有类密钥`NSFileProtectionNone`都使用从设备 UID 和用户密码派生的密钥进行加密。因此，解密只能在设备本身上进行，并且需要正确的密码。

从 iOS 7 开始，默认的数据保护等级是“Protected Until First User Authentication”。

#### 钥匙扣[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#the-keychain)

iOS Keychain 可用于安全地存储简短、敏感的数据位，例如加密密钥和会话令牌。它作为一个 SQLite 数据库实现，只能通过 Keychain API 访问。

在 macOS 上，每个用户应用程序都可以根据需要创建任意数量的钥匙串，并且每个登录帐户都有自己的钥匙串。[iOS 上的 Keychain 结构](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html)不同：只有一个 Keychain 可用于所有应用程序。通过attribute的[访问组功能](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/AddingCapabilities/AddingCapabilities.html)，可以在由同一开发人员签名的应用程序之间共享对项目的访问[`kSecAttrAccessGroup`](https://developer.apple.com/documentation/security/ksecattraccessgroup)。对 Keychain 的访问由`securityd`守护程序管理，它根据应用程序的 、 和 授权授予`Keychain-access-groups`访问`application-identifier`权限`application-group`。

[Keychain API](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html)包括以下主要操作：

- `SecItemAdd`
- `SecItemUpdate`
- `SecItemCopyMatching`
- `SecItemDelete`

存储在 Keychain 中的数据通过类似于用于文件加密的类结构的类结构来保护。添加到 Keychain 的项目被编码为二进制 plist，并在 Galois/Counter Mode (GCM) 中使用 128 位 AES 每项目密钥加密。请注意，较大的数据块并不意味着直接保存在钥匙串中——这就是数据保护 API 的用途。您可以通过在对或`kSecAttrAccessible`的调用中设置密钥来为钥匙串项目配置数据保护。kSecAttrAccessible的以下可配置[可访问性值](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values#1679100)是钥匙串数据保护类：`SecItemAdd``SecItemUpdate`

- `kSecAttrAccessibleAlways`：Keychain 项中的数据始终可以访问，无论设备是否被锁定。
- `kSecAttrAccessibleAlwaysThisDeviceOnly`：Keychain 项中的数据始终可以访问，无论设备是否被锁定。数据不会包含在 iCloud 或本地备份中。
- `kSecAttrAccessibleAfterFirstUnlock`：Keychain 项中的数据在重启后无法访问，直到设备被用户解锁一次。
- `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`：Keychain 项中的数据在重启后无法访问，直到设备被用户解锁一次。具有此属性的项目不会迁移到新设备。因此，从不同设备的备份恢复后，这些项目将不存在。
- `kSecAttrAccessibleWhenUnlocked`：钥匙串项中的数据只有在用户解锁设备时才能访问。
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`：钥匙串项中的数据只有在用户解锁设备时才能访问。数据不会包含在 iCloud 或本地备份中。
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`：钥匙串中的数据只有在设备解锁时才能访问。只有在设备上设置了密码时，此保护等级才可用。数据不会包含在 iCloud 或本地备份中。

`AccessControlFlags`定义用户可以验证密钥 ( `SecAccessControlCreateFlags`) 的机制：

- `kSecAccessControlDevicePasscode`：通过密码访问项目。
- `kSecAccessControlBiometryAny`：通过注册到 Touch ID 的指纹之一访问该项目。添加或删除指纹不会使该项目无效。
- `kSecAccessControlBiometryCurrentSet`：通过注册到 Touch ID 的指纹之一访问该项目。添加或删除指纹*会使*该项目无效。
- `kSecAccessControlUserPresence`：通过任一已注册指纹（使用 Touch ID）或默认密码访问项目。

请注意，由 Touch ID（通过`kSecAccessControlBiometryAny`或`kSecAccessControlBiometryCurrentSet`）保护的密钥受 Secure Enclave 保护：钥匙串仅持有令牌，而非实际密钥。密钥驻留在 Secure Enclave 中。

从 iOS 9 开始，您可以在 Secure Enclave 中进行基于 ECC 的签名操作。在这种情况下，私钥和加密操作驻留在 Secure Enclave 中。有关创建 ECC 密钥的更多信息，请参阅静态分析部分。iOS 9 仅支持 256 位 ECC。此外，您需要将公钥存储在 Keychain 中，因为它不能存储在 Secure Enclave 中。创建密钥后，您可以使用`kSecAttrKeyType`来指示要使用该密钥的算法类型。

如果您想使用这些机制，建议测试密码是否已设置。在 iOS 8 中，您需要检查是否可以从受`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`属性保护的钥匙串中的项目读取/写入。从 iOS 9 开始，您可以检查是否设置了锁定屏幕，使用`LAContext`：

Swift:

```
public func devicePasscodeEnabled() -> Bool {
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
}
```

Objective-C：

```
-(BOOL)devicePasscodeEnabled:(LAContex)context{
  if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil]) {
        return true;
    } else {
        return false;
    }
}
```

##### 钥匙串数据持久化[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#keychain-data-persistence)

在 iOS 上，当应用程序被卸载时，应用程序使用的 Keychain 数据会保留在设备中，这与应用程序沙箱存储的数据被擦除不同。如果用户在未执行恢复出厂设置的情况下出售其设备，设备的购买者可能能够通过重新安装先前用户使用的相同应用程序来访问先前用户的应用程序帐户和数据。这不需要技术能力来执行。

在评估 iOS 应用程序时，您应该寻找钥匙串数据持久性。这通常是通过使用应用程序生成可能存储在 Keychain 中的示例数据、卸载应用程序、然后重新安装应用程序以查看数据是否在应用程序安装之间保留。使用反对Runtime(运行时)移动探索工具包转储钥匙串数据。以下`objection`命令演示了此过程：

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios keychain dump
Note: You may be asked to authenticate using the devices passcode or TouchID
Save the output by adding `--json keychain.json` to this command
Dumping the iOS keychain...
Created                    Accessible                      ACL    Type      Account                    Service                                                        Data
-------------------------  ------------------------------  -----  --------  -------------------------  -------------------------------------------------------------  ------------------------------------
2020-02-11 13:26:52 +0000  WhenUnlocked                    None   Password  keychainValue              com.highaltitudehacks.DVIAswiftv2.develop                      mysecretpass123
```

没有可供开发人员在卸载应用程序时强制擦除数据的 iOS API。相反，开发人员应该采取以下步骤来防止钥匙串数据在应用程序安装之间持续存在：

- 安装后首次启动应用程序时，擦除与该应用程序关联的所有钥匙串数据。这将防止设备的第二个用户意外获得对前一个用户帐户的访问权限。以下 Swift 示例是此擦除过程的基本演示：

```
let userDefaults = UserDefaults.standard

if userDefaults.bool(forKey: "hasRunBefore") == false {
    // Remove Keychain items here

    // Update the flag indicator
    userDefaults.set(true, forKey: "hasRunBefore")
    userDefaults.synchronize() // Forces the app to update UserDefaults
}
```

- 在为 iOS 应用程序开发注销功能时，请确保钥匙串数据作为帐户注销的一部分被擦除。这将允许用户在卸载应用程序之前清除他们的帐户。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis)

当您有权访问 iOS 应用程序的源代码时，请识别在整个应用程序中保存和处理的敏感数据。这包括密码、密钥和个人身份信息 (PII)，但也可能包括行业法规、法律和公司政策认定为敏感的其他数据。查找通过下面列出的任何本地存储 API 保存的数据。

确保在没有适当保护的情况下绝不会存储敏感数据。例如，身份验证令牌不应在`NSUserDefaults`没有额外加密的情况下保存。还要避免将加密密钥存储在`.plist`文件中，在代码中硬编码为字符串，或使用可预测的混淆函数或基于稳定属性的密钥派生函数生成。

敏感数据应使用 Keychain API（将它们存储在 Secure Enclave 中）进行存储，或使用信封加密进行加密存储。信封加密或密钥包装是一种使用对称加密来封装密钥材料的密码结构。数据加密密钥 (DEK) 可以使用必须安全存储在钥匙串中的密钥加密密钥 (KEK) 进行加密。加密的 DEK 可以存储`NSUserDefaults`或写入文件。需要时，应用程序读取 KEK，然后解密 DEK。请参阅[OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys)以了解有关加密密钥的更多信息。

#### 钥匙链[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#keychain)

必须实施加密，以便将密钥存储在具有安全设置的钥匙串中，理想情况下`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`。这确保了硬件支持的存储机制的使用。确保`AccessControlFlags`根据 KeyChain 中密钥的安全策略进行设置。

[使用 KeyChain](https://developer.apple.com/library/content/samplecode/GenericKeychain/Introduction/Intro.html#//apple_ref/doc/uid/DTS40007797-Intro-DontLinkElementID_2)存储、更新和删除数据的一般示例可以在官方 Apple 文档中找到。Apple 官方文档还包括使用[Touch ID 和密码保护键](https://developer.apple.com/documentation/localauthentication/accessing_keychain_items_with_face_id_or_touch_id)的示例。

以下是可用于创建密钥的示例 Swift 代码（注意`kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave`：这表示我们想直接使用 Secure Enclave。）：

```
// private key parameters
let privateKeyParams = [
    kSecAttrLabel as String: "privateLabel",
    kSecAttrIsPermanent as String: true,
    kSecAttrApplicationTag as String: "applicationTag",
] as CFDictionary

// public key parameters
let publicKeyParams = [
    kSecAttrLabel as String: "publicLabel",
    kSecAttrIsPermanent as String: false,
    kSecAttrApplicationTag as String: "applicationTag",
] as CFDictionary

// global parameters
let parameters = [
    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPublicKeyAttrs as String: publicKeyParams,
    kSecPrivateKeyAttrs as String: privateKeyParams,
] as CFDictionary

var pubKey, privKey: SecKey?
let status = SecKeyGeneratePair(parameters, &pubKey, &privKey)

if status != errSecSuccess {
    // Keys created successfully
}
```

在检查 iOS 应用程序的不安全数据存储时，请考虑以下存储数据的方法，因为默认情况下它们都不会加密数据：

#### `NSUserDefaults`[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#nsuserdefaults)

该类[`NSUserDefaults`](https://developer.apple.com/documentation/foundation/nsuserdefaults)提供了一个用于与默认系统交互的编程接口。默认系统允许应用程序根据用户偏好自定义其行为。保存的数据`NSUserDefaults`可以在应用程序包中查看。此类将数据存储在 plist 文件中，但它旨在用于少量数据。

#### 文件系统[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#file-system)

- `NSData`：创建静态数据对象，同时`NSMutableData`创建动态数据对象。`NSData`并且`NSMutableData`通常用于数据存储，但它们也可用于分布式对象应用程序，其中数据对象中包含的数据可以在应用程序之间复制或移动。以下是用于写入`NSData`对象的方法：
- `NSDataWritingWithoutOverwriting`
- `NSDataWritingFileProtectionNone`
- `NSDataWritingFileProtectionComplete`
- `NSDataWritingFileProtectionCompleteUnlessOpen`
- `NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication`
- `writeToFile`：将数据存储为`NSData`类的一部分
- `NSSearchPathForDirectoriesInDomains, NSTemporaryDirectory`: 用于管理文件路径
- `NSFileManager`：让您检查和更改文件系统的内容。您可以使用`createFileAtPath`创建一个文件并写入它。

以下示例显示如何使用该类创建`complete`加密文件。`FileManager`您可以在 Apple 开发人员文档[“加密您的应用程序的文件”中找到更多信息](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files)

Swift:

```
FileManager.default.createFile(
    atPath: filePath,
    contents: "secret text".data(using: .utf8),
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

Objective-C：

```
[[NSFileManager defaultManager] createFileAtPath:[self filePath]
  contents:[@"secret text" dataUsingEncoding:NSUTF8StringEncoding]
  attributes:[NSDictionary dictionaryWithObject:NSFileProtectionComplete
  forKey:NSFileProtectionKey]];
```

#### 核心数据[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#coredata)

[`Core Data`](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/CoreData/nsfetchedresultscontroller.html#//apple_ref/doc/uid/TP40001075-CH8-SW1)是一个用于管理应用程序中对象模型层的框架。它为与对象生命周期和对象图管理（包括持久性）相关的常见任务提供了通用和自动化的解决方案。[Core Data 可以使用 SQLite 作为它的持久化存储](https://cocoacasts.com/what-is-the-difference-between-core-data-and-sqlite/)，但是这个框架本身并不是一个数据库。

默认情况下，CoreData 不加密它的数据。作为 MITRE Corporation 专注于开源 iOS 安全控制的研究项目 (iMAS) 的一部分，可以向 CoreData 添加一个额外的加密层。有关详细信息，请参阅[GitHub 存储库。](https://github.com/project-imas/encrypted-core-data)

#### SQLite 数据库[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#sqlite-databases)

如果应用程序要使用 SQLite，则必须将 SQLite 3 库添加到应用程序。这个库是一个 C++ 包装器，它为 SQLite 命令提供了一个 API。

#### Firebase 实时数据库[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#firebase-real-time-databases)

Firebase 是一个拥有超过 15 种产品的开发平台，其中之一就是 Firebase Real-time Database。应用程序开发人员可以利用它来存储数据并与 NoSQL 云托管数据库同步。数据以 JSON 格式存储，并实时同步到每个连接的客户端，即使在应用程序离线时也仍然可用。

可以通过进行以下网络调用来识别配置错误的 Firebase 实例：

```
https://\<firebaseProjectName\>.firebaseio.com/.json
```

可以从属性列表 (.plist) 文件中检索firebaseProjectName *。*例如key在*GoogleService-Info.plist*文件`PROJECT_ID`中存放了对应的Firebase项目名称。

或者，分析师可以使用[Firebase Scanner](https://github.com/shivsahni/FireBaseScanner)，这是一个自动执行上述任务的 python 脚本，如下所示：

```
python FirebaseScanner.py -f <commaSeparatedFirebaseProjectNames>
```

#### Realm Databases[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#realm-databases)

[Apple 不提供Realm Objective-C](https://realm.io/docs/objc/latest/)和[Realm Swift](https://realm.io/docs/swift/latest/)，但它们仍然值得注意。它们存储所有未加密的内容，除非配置启用了加密。

以下示例演示了如何对 Realm 数据库使用加密：

```
// Open the encrypted Realm file where getKey() is a method to obtain a key from the Keychain or a server
let config = Realm.Configuration(encryptionKey: getKey())
do {
  let realm = try Realm(configuration: config)
  // Use the Realm as normal
} catch let error as NSError {
  // If the encryption key is wrong, `error` will say that it's an invalid database
  fatalError("Error opening realm: \(error)")
}
```

#### Couchbase Lite 数据库[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#couchbase-lite-databases)

[Couchbase Lite](https://github.com/couchbase/couchbase-lite-ios)是一个轻量级、嵌入式、面向文档 (NoSQL) 的数据库引擎，可以同步。它为 iOS 和 macOS Native编译。

#### Yap数据库[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#yapdatabase)

[YapDatabase](https://github.com/yapstudios/YapDatabase)是建立在 SQLite 之上的键/值存储。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis)

在不利用Native iOS 功能的情况下确定敏感信息（如凭据和密钥）是否存储不安全的一种方法是分析应用程序的数据目录。在分析数据之前触发所有应用程序功能很重要，因为应用程序可能仅在触发特定功能后才存储敏感数据。然后，您可以根据通用关键字和特定于应用程序的数据对数据转储进行静态分析。

以下步骤可用于确定应用程序如何在越狱的 iOS 设备上本地存储数据：

1. 触发存储潜在敏感数据的功能。
2. 连接到 iOS 设备并导航到其 Bundle 目录（这适用于 iOS 8.0 及更高版本）：`/var/mobile/Containers/Data/Application/$APP_ID/`
3. 使用您存储的数据执行 grep，例如：`grep -iRn "USERID"`。
4. 如果敏感数据以明文形式存储，则该应用无法通过此测试。

您可以使用第三方应用程序（例如[iMazing](https://imazing.com/) ）在未越狱的 iOS 设备上分析应用程序的数据目录。

1. 触发存储潜在敏感数据的功能。
2. 将 iOS 设备连接到主机并启动 iMazing。
3. 选择“应用程序”，右键单击所需的 iOS 应用程序，然后选择“提取应用程序”。
4. 导航到输出目录并找到`$APP_NAME.imazing`. 将其重命名为`$APP_NAME.zip`.
5. 解压缩 ZIP 文件。然后您可以分析应用程序数据。

> 请注意，像 iMazing 这样的工具不会直接从设备复制数据。他们试图从他们创建的备份中提取数据。因此，获取存储在 iOS 设备上的所有应用程序数据是不可能的：并非所有文件夹都包含在备份中。使用越狱设备或使用 Frida 重新打包应用程序，并使用objection等工具访问所有数据和文件。

如果您将 Frida 库添加到应用程序并按照“非越狱设备上的动态分析”（来自“iOS 上的篡改和逆向工程”一章）中的描述重新打包，您可以使用[反对](https://github.com/sensepost/objection)直接从应用程序的数据传输文件目录或[读取反对文件，](https://github.com/sensepost/objection/wiki/Using-objection#getting-started-ios-edition)如“iOS 上的基本安全测试”一章“[主机设备数据传输](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#host-device-data-transfer)”一节中所述。

Keychain 内容可以在动态分析期间转储。在越狱设备上，您可以按照“iOS 上的基本安全测试”一章中的说明使用[钥匙串转储程序。](https://github.com/ptoomey3/Keychain-Dumper/)

钥匙串文件的路径是

```
/private/var/Keychains/keychain-2.db
```

在非越狱设备上，您可以使用 objection 来[转储](https://github.com/sensepost/objection/wiki/Notes-About-The-Keychain-Dumper)应用程序创建和存储的钥匙串项目。

#### 使用 Xcode 和 iOS 模拟器进行动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis-with-xcode-and-ios-simulator)

> 此测试仅适用于 macOS，因为需要 Xcode 和 iOS 模拟器。

要测试本地存储并验证其中存储了哪些数据，并不一定要有 iOS 设备。通过访问源代码和 Xcode，可以在 iOS 模拟器中构建和部署应用程序。iOS模拟器当前设备的文件系统为`~/Library/Developer/CoreSimulator/Devices`.

应用程序在 iOS 模拟器中运行后，您可以导航到使用以下命令启动的最新模拟器的目录：

```
$ cd ~/Library/Developer/CoreSimulator/Devices/$(
ls -alht ~/Library/Developer/CoreSimulator/Devices | head -n 2 |
awk '{print $9}' | sed -n '1!p')/data/Containers/Data/Application
```

上面的命令会自动找到最新启动的模拟器的UUID。现在您仍然需要 grep 查找您的应用名称或应用中的关键字。这将向您显示应用程序的 UUID。

```
grep -iRn keyword .
```

然后，您可以监视和验证应用程序文件系统的变化，并调查在使用该应用程序时文件中是否存储了任何敏感信息。

#### 有objection的动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis-with-objection)

您可以使用[反对](https://github.com/sensepost/objection)Runtime(运行时)移动探索工具包来查找由应用程序的数据存储机制引起的漏洞。可以在没有越狱设备的情况下使用 Objection，但它需要[修补 iOS 应用程序](https://github.com/sensepost/objection/wiki/Patching-iOS-Applications)。

##### 阅读钥匙串[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#reading-the-keychain)

要使用 Objection 读取 Keychain，请执行以下命令：

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios keychain dump
Note: You may be asked to authenticate using the devices passcode or TouchID
Save the output by adding `--json keychain.json` to this command
Dumping the iOS keychain...
Created                    Accessible                      ACL    Type      Account                    Service                                                        Data
-------------------------  ------------------------------  -----  --------  -------------------------  -------------------------------------------------------------  ------------------------------------
2020-02-11 13:26:52 +0000  WhenUnlocked                    None   Password  keychainValue              com.highaltitudehacks.DVIAswiftv2.develop                      mysecretpass123
```

##### 搜索二进制 COOKIE[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#searching-for-binary-cookies)

iOS 应用程序通常将二进制 cookie 文件存储在应用程序沙箱中。Cookie 是包含应用程序 WebView 的 cookie 数据的二进制文件。您可以使用 objection 将这些文件转换为 JSON 格式并检查数据。

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios cookies get --json
[
    {
        "domain": "highaltitudehacks.com",
        "expiresDate": "2051-09-15 07:46:43 +0000",
        "isHTTPOnly": "false",
        "isSecure": "false",
        "name": "username",
        "path": "/",
        "value": "admin123",
        "version": "0"
    }
]
```

##### 搜索属性列表文件[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#searching-for-property-list-files)

iOS 应用程序通常将数据存储在属性列表 (plist) 文件中，这些文件存储在应用程序沙箱和 IPA 包中。有时这些文件包含敏感信息，例如用户名和密码；因此，在 iOS 评估期间应检查这些文件的内容。使用`ios plist cat plistFileName.plist`命令检查 plist 文件。

要查找文件 userInfo.plist，请使用`env`命令。它将打印出应用程序库、缓存和文档目录的位置：

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # env
Name               Path
-----------------  -------------------------------------------------------------------------------------------
BundlePath         /private/var/containers/Bundle/Application/B2C8E457-1F0C-4DB1-8C39-04ACBFFEE7C8/DVIA-v2.app
CachesDirectory    /var/mobile/Containers/Data/Application/264C23B8-07B5-4B5D-8701-C020C301C151/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/264C23B8-07B5-4B5D-8701-C020C301C151/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/264C23B8-07B5-4B5D-8701-C020C301C151/Library
```

转到 Documents 目录并列出所有使用`ls`.

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ls
NSFileType      Perms  NSFileProtection                      Read    Write    Owner         Group         Size      Creation                   Name
------------  -------  ------------------------------------  ------  -------  ------------  ------------  --------  -------------------------  ------------------------
Directory         493  n/a                                   True    True     mobile (501)  mobile (501)  192.0 B   2020-02-12 07:03:51 +0000  default.realm.management
Regular           420  CompleteUntilFirstUserAuthentication  True    True     mobile (501)  mobile (501)  16.0 KiB  2020-02-12 07:03:51 +0000  default.realm
Regular           420  CompleteUntilFirstUserAuthentication  True    True     mobile (501)  mobile (501)  1.2 KiB   2020-02-12 07:03:51 +0000  default.realm.lock
Regular           420  CompleteUntilFirstUserAuthentication  True    True     mobile (501)  mobile (501)  284.0 B   2020-05-29 18:15:23 +0000  userInfo.plist
Unknown           384  n/a                                   True    True     mobile (501)  mobile (501)  0.0 B     2020-02-12 07:03:51 +0000  default.realm.note

Readable: True  Writable: True
```

执行`ios plist cat`命令检查 userInfo.plist 文件的内容。

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios plist cat userInfo.plist
{
        password = password123;
        username = userName;
}
```

##### 搜索 SQLITE 数据库[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#searching-for-sqlite-databases)

iOS 应用程序通常使用 SQLite 数据库来存储应用程序所需的数据。测试人员应检查这些文件的数据保护值及其敏感数据的内容。对象包含一个与 SQLite 数据库交互的模块。它允许转储模式、它们的表并查询记录。

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # sqlite connect Model.sqlite
Caching local copy of database file...
Downloading /var/mobile/Containers/Data/Application/264C23B8-07B5-4B5D-8701-C020C301C151/Library/Application Support/Model.sqlite to /var/folders/4m/dsg0mq_17g39g473z0996r7m0000gq/T/tmpdr_7rvxi.sqlite
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /var/mobile/Containers/Data/Application/264C23B8-07B5-4B5D-8701-C020C301C151/Library/Application Support/Model.sqlite to /var/folders/4m/dsg0mq_17g39g473z0996r7m0000gq/T/tmpdr_7rvxi.sqlite
Validating SQLite database format
Connected to SQLite database at: Model.sqlite

SQLite @ Model.sqlite > .tables
+--------------+
| name         |
+--------------+
| ZUSER        |
| Z_METADATA   |
| Z_MODELCACHE |
| Z_PRIMARYKEY |
+--------------+
Time: 0.013s

SQLite @ Model.sqlite > select * from Z_PRIMARYKEY
+-------+--------+---------+-------+
| Z_ENT | Z_NAME | Z_SUPER | Z_MAX |
+-------+--------+---------+-------+
| 1     | User   | 0       | 0     |
+-------+--------+---------+-------+
1 row in set
Time: 0.013s
```

##### 搜索缓存数据库[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#searching-for-cache-databases)

默认情况下，NSURLSession 在 Cache.db 数据库中存储数据，例如 HTTP 请求和响应。如果已缓存令牌、用户名或任何其他敏感信息，则此数据库可能包含敏感数据。要查找缓存的信息，请打开应用程序 ( `/var/mobile/Containers/Data/Application/<UUID>`) 的数据目录并转到 `/Library/Caches/<Bundle Identifier>`. WebKit 缓存也存储在 Cache.db 文件中。Object 可以使用命令打开数据库并与之交互`sqlite connect Cache.db`，因为它是一个普通的 SQLite 数据库。

建议禁用缓存此数据，因为它可能在请求或响应中包含敏感信息。以下列表显示了实现此目的的不同方法：

1. 建议在注销后删除缓存的响应。这可以通过 Apple 提供的方法来完成，[`removeAllCachedResponses`](https://developer.apple.com/documentation/foundation/urlcache/1417802-removeallcachedresponses) 您可以按如下方式调用此方法：

```
URLCache.shared.removeAllCachedResponses()
```

此方法将从 Cache.db 文件中删除所有缓存的请求和响应。

1. 如果您不需要使用 cookie 的优势，建议只使用 URLSession 的[.ephemeral](https://developer.apple.com/documentation/foundation/urlsessionconfiguration/1410529-ephemeral)配置属性，这将禁用保存 cookie 和缓存。

[苹果文档](https://developer.apple.com/documentation/foundation/urlsessionconfiguration/1410529-ephemeral)：

```
An ephemeral session configuration object is similar to a default session configuration (see default), except that the corresponding session object doesn’t store caches, credential stores, or any session-related data to disk. Instead, session-related data is stored in RAM. The only time an ephemeral session writes data to disk is when you tell it to write the contents of a URL to a file.
```

1. 也可以通过将缓存策略设置为[.notAllowed](https://developer.apple.com/documentation/foundation/urlcache/storagepolicy/notallowed)来禁用缓存。它将禁用以任何方式存储缓存，无论是在内存中还是在磁盘上。

## 检查敏感数据的日志 (MSTG-STORAGE-3)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#checking-logs-for-sensitive-data-mstg-storage-3)

在移动设备上创建日志文件有很多正当理由，包括跟踪设备离线时本地存储的崩溃或错误（以便在线时将它们发送给应用程序开发人员），以及存储使用统计信息。但是，记录信用卡号和会话信息等敏感数据可能会将数据暴露给攻击者或恶意应用程序。可以通过多种方式创建日志文件。以下列表显示了 iOS 上可用的方法：

- NSLog 方法
- 类似 printf 的函数
- 类 NSAssert 函数
- 宏观

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_1)

使用以下关键字检查应用程序的源代码以获取预定义和自定义的日志记录语句：

- 对于预定义和内置函数：
- 日志
- NS断言
- NSC断言
- 打印函数
- 对于自定义函数：
- 记录
- 日志文件

解决此问题的通用方法是使用定义来启用`NSLog`用于开发和调试的语句，然后在发布软件之前禁用它们。您可以通过将以下代码添加到适当的 PREFIX_HEADER (*.pch) 文件来执行此操作：

```
#ifdef DEBUG
#   define NSLog (...) NSLog(__VA_ARGS__)
#else
#   define NSLog (...)
#endif
```

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_1)

在“iOS 基本安全测试”一章的“监控系统日志”部分，解释了检查设备日志的各种方法。导航到显示包含敏感用户信息的输入字段的屏幕。

启动其中一种方法后，填写输入字段。如果输出中显示敏感数据，则应用程序无法通过此测试。

## 确定敏感数据是否与第三方共享 (MSTG-STORAGE-4)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#determining-whether-sensitive-data-is-shared-with-third-parties-mstg-storage-4)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#overview)

敏感信息可能会通过多种方式泄露给第三方。在 iOS 上，通常通过应用程序中嵌入的第三方服务。

这些服务提供的功能可能涉及跟踪服务以监控用户在使用应用程序时的行为、销售横幅广告或改善用户体验。

缺点是开发人员通常不知道通过第三方库执行的代码的细节。因此，不应向服务发送超过必要的信息，也不应泄露敏感信息。

大多数第三方服务以两种方式实现：

- 有一个独立的库
- 使用完整的 SDK

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_2)

要确定第三方库提供的 API 调用和函数是否根据最佳实践使用，请查看其源代码、请求的权限并检查是否存在任何已知漏洞（请参阅[“检查第三方库中的弱点 (MSTG-CODE-5) ）”](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#checking-for-weaknesses-in-third-party-libraries-mstg-code-5)）。

发送到第三方服务的所有数据都应匿名，以防止泄露 PII（个人身份信息），从而允许第三方识别用户帐户。不应将其他数据（例如可以映射到用户帐户或会话的 ID）发送给第三方。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_2)

检查对外部服务的所有请求以获取嵌入的敏感信息。[要拦截客户端和服务器之间的流量，您可以通过使用Burp Suite](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#burp-suite) Professional 或[OWASP ZAP](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#owasp-zap)发起中间人 (MITM) 攻击来执行动态分析。通过拦截代理路由流量后，您可以尝试嗅探在应用程序和服务器之间传递的流量。应检查所有未直接发送到托管主要功能的服务器的应用程序请求是否包含敏感信息，例如跟踪器或广告服务中的 PII。

## 在键盘缓存中查找敏感数据 (MSTG-STORAGE-5)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#finding-sensitive-data-in-the-keyboard-cache-mstg-storage-5)

用户可以使用多个用于简化键盘输入的选项。这些选项包括自动更正和拼写检查。大多数键盘输入默认缓存在`/private/var/mobile/Library/Keyboard/dynamic-text.dat`.

UITextInputTraits[协议](https://developer.apple.com/reference/uikit/uitextinputtraits)用于键盘缓存。UITextField、UITextView 和 UISearchBar 类自动支持此协议并提供以下属性：

- `var autocorrectionType: UITextAutocorrectionType`确定是否在键入期间启用自动更正。启用自动更正后，文本对象会跟踪未知单词并建议合适的替换，自动替换键入的文本，除非用户覆盖替换。此属性的默认值为`UITextAutocorrectionTypeDefault`，对于大多数输入法启用自动更正。
- `var secureTextEntry: BOOL`确定是否禁用文本复制和文本缓存并隐藏为 . 输入的文本`UITextField`。此属性的默认值为`NO`。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_3)

- 在源代码中搜索类似的实现，例如

```
  textObject.autocorrectionType = UITextAutocorrectionTypeNo;
  textObject.secureTextEntry = YES;
```

- 在 Xcode 中打开 xib 和情节提要文件，`Interface Builder`并验证相应对象的`Secure Text Entry`和`Correction`中的状态。`Attributes Inspector`

应用程序必须防止缓存输入到文本字段中的敏感信息。`textObject.autocorrectionType = UITextAutocorrectionTypeNo`您可以通过在所需的 UITextFields、UITextViews 和 UISearchBars 中使用指令以编程方式禁用缓存来防止缓存。对于应该屏蔽的数据，例如 PIN 和密码，设置`textObject.secureTextEntry`为`YES`.

```
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_3)

如果有越狱的 iPhone，请执行以下步骤：

1. 通过导航到重置您的 iOS 设备键盘缓存`Settings > General > Reset > Reset Keyboard Dictionary`。
2. 使用该应用程序并确定允许用户输入敏感数据的功能。
3. 将键盘缓存文件转储`dynamic-text.dat`到以下目录（iOS 8.0 之前的版本可能不同）： `/private/var/mobile/Library/Keyboard/`
4. 查找敏感数据，例如用户名、密码、电子邮件地址和信用卡号。如果可以通过键盘缓存文件获取敏感数据，则应用程序无法通过此测试。

```
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

如果您必须使用未越狱的 iPhone：

1. 重置键盘缓存。
2. 键入所有敏感数据。
3. 再次使用该应用程序并确定自动更正是否会提示之前输入的敏感信息。

## 确定是否通过 IPC 机制暴露敏感数据 (MSTG-STORAGE-6)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#determining-whether-sensitive-data-is-exposed-via-ipc-mechanisms-mstg-storage-6)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#overview_1)

[进程间通信 (IPC)](https://nshipster.com/inter-process-communication/)允许进程相互发送消息和数据。对于需要相互通信的进程，在iOS上有不同的IPC实现方式：

- **[XPC 服务](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)**：XPC 是一个结构化的异步库，提供基本的进程间通信。它由 管理`launchd`。它是 iOS 上最安全、最灵活的 IPC 实现，应该是首选方法。它在可能的最受限制的环境中运行：沙盒化，没有 root 权限升级和最小的文件系统访问和网络访问。XPC 服务使用了两种不同的 API：
- NSXPCConnection API
- XPC 服务 API
- **[Mach Ports](https://developer.apple.com/documentation/foundation/nsmachport)**：所有 IPC 通信最终都依赖于 Mach Kernel API。Mach 端口仅允许本地通信（设备内通信）。它们可以本地实现，也可以通过 Core Foundation (CFMachPort) 和 Foundation (NSMachPort) 包装器实现。
- **NSFileCoordinator**：该类`NSFileCoordinator`可用于通过本地文件系统上可用的文件向各种进程管理应用程序和从应用程序发送数据。[NSFileCoordinator](https://www.atomicbird.com/blog/sharing-with-app-extensions)方法同步运行，因此您的代码将被阻塞，直到它们停止执行。这很方便，因为您不必等待异步块回调，但这也意味着这些方法会阻塞正在运行的线程。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_4)

以下部分总结了在 iOS 源代码中识别 IPC 实现时应查找的关键字。

#### XPC 服务[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#xpc-services)

可以使用几个类来实现 NSXPCConnection API：

- NSXPC连接
- NSXPC接口
- NSXPCListener
- NSXPCListenerEndpoint

您可以为连接设置[安全属性](https://www.objc.io/issues/14-mac/xpc/#security-attributes-of-the-connection)。应验证属性。

在 Xcode 项目中检查 XPC Services API（基于 C）的以下两个文件：

- [`xpc.h`](https://developer.apple.com/documentation/xpc/xpc_services_xpc.h)
- `connection.h`

#### 马赫端口[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#mach-ports)

在低级实现中寻找的关键字：

- mach_port_t
- mach_msg_*

在高级实现中寻找的关键字（Core Foundation 和 Foundation wrappers）：

- CFMach端口
- CFMessagePort
- NSM端口
- NMSessage端口

#### NS文件协调器[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#nsfilecoordinator)

要查找的关键字：

- NS文件协调器

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_4)

通过 iOS 源代码的静态分析验证 IPC 机制。当前没有可用于验证 IPC 使用情况的 iOS 工具。

## 检查通过用户界面公开的敏感数据 (MSTG-STORAGE-7)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#checking-for-sensitive-data-disclosed-through-the-user-interface-mstg-storage-7)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#overview_2)

例如，在注册帐户或付款时输入敏感信息是使用许多应用程序的重要部分。此数据可能是财务信息，例如信用卡数据或用户帐户密码。如果应用程序在键入时未正确屏蔽数据，则数据可能会暴露。

为了防止泄露和减轻诸如[肩窥](https://en.wikipedia.org/wiki/Shoulder_surfing_(computer_security))之类的风险，您应该验证没有通过用户界面暴露任何敏感数据，除非明确要求（例如输入密码）。对于需要显示的数据，应该对其进行适当的屏蔽，通常是显示星号或点而不是明文。

仔细检查所有显示此类信息或将其作为输入的 UI 组件。搜索敏感信息的任何痕迹，并评估是否应将其屏蔽或完全删除。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_5)

可以通过两种方式配置屏蔽其输入的文本字段：

**故事板** 在 iOS 项目的故事板中，导航到获取敏感数据的文本字段的配置选项。确保选择了“安全文本输入”选项。如果激活此选项，则文本字段中会显示点以代替文本输入。

**源代码** 如果源代码中定义了文本字段，请确保该选项[`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/1624427-issecuretextentry)设置为“true”。此选项通过显示点来遮盖文本输入。

```
sensitiveTextField.isSecureTextEntry = true
```

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_5)

要确定应用程序是否向用户界面泄露了任何敏感信息，请运行应用程序并识别显示此类信息或将其作为输入的组件。

如果信息被星号或点等遮盖，则应用不会向用户界面泄露数据。

## 测试敏感数据的备份 (MSTG-STORAGE-8)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#testing-backups-for-sensitive-data-mstg-storage-8)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#overview_3)

iOS 包含自动备份功能，可以创建存储在设备上的数据的副本。您可以使用 iTunes（直到 macOS Catalina）或 Finder（从 macOS Catalina 开始）或通过 iCloud 备份功能从您的主机进行 iOS 备份。在这两种情况下，备份包括几乎所有存储在 iOS 设备上的数据，除了高度敏感的数据，如 Apple Pay 信息和 Touch ID 设置。

由于 iOS 备份已安装的应用程序及其数据，一个明显的问题是应用程序存储的敏感用户数据是否会无意中通过备份泄漏。另一个不太明显的问题是，用于保护数据或限制应用程序功能的敏感配置设置是否会在恢复修改后的备份后被篡改以更改应用程序行为。这两个担忧都是有道理的，并且这些漏洞已被证明存在于当今大量的应用程序中。

#### 如何备份钥匙串[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#how-the-keychain-is-backed-up)

当用户备份他们的 iOS 设备时，Keychain 数据也会被备份，但 Keychain 中的秘密仍然是加密的。解密钥匙串数据所需的类密钥不包含在备份中。恢复钥匙串数据需要将备份恢复到设备并使用用户密码解锁设备。

设置了该`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`属性的钥匙串项只有在备份恢复到备份设备时才能解密。试图从备份中提取此钥匙串数据的人无法在不访问原始设备内的加密硬件的情况下对其进行解密。

然而，使用 Keychain 的一个警告是，它仅设计用于存储少量用户数据或简短笔记（根据 Apple 的[Keychain Services文档](https://developer.apple.com/documentation/security/keychain_services)). 这意味着具有较大本地安全存储需求的应用程序（例如，消息传递应用程序等）应该加密应用程序容器内的数据，但使用钥匙串来存储密钥材料。如果敏感的配置设置（例如，数据丢失防护策略、密码策略、合规性策略等）必须在应用程序容器中保持未加密状态，您可以考虑将策略的散列存储在钥匙串中以进行完整性检查。如果没有完整性检查，这些设置可以在备份中修改，然后恢复回设备以修改应用程序行为（例如，更改配置的远程端点）或安全设置（例如，越狱检测、证书固定、最大 UI 登录尝试等） .).

要点：如果按照本章前面的建议处理敏感数据（例如，存储在 Keychain 中，使用 Keychain 支持的完整性检查，或使用锁定在 Keychain 中的密钥加密），备份不应该成为安全问题。

#### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_6)

安装了移动应用程序的设备的备份将包括[应用程序私有目录](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12)`Library/Caches/`中的所有子目录（除了）和文件。

因此，请避免在应用的私有目录或子目录中的任何文件或文件夹中以明文形式存储敏感数据。

虽然默认情况下始终备份`Documents/`和中的所有文件，但您可以通过调用key将[文件从备份中排除。](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28)`Library/Application Support/``NSURL setResourceValue:forKey:error:``NSURLIsExcludedFromBackupKey`

您可以使用[NSURLIsExcludedFromBackupKey](https://developer.apple.com/reference/foundation/nsurl#//apple_ref/c/data/NSURLIsExcludedFromBackupKey)和[CFURLIsExcludedFromBackupKey](https://developer.apple.com/reference/corefoundation/cfurl-rd7#//apple_ref/c/data/kCFURLIsExcludedFromBackupKey)文件系统属性从备份中排除文件和目录。需要排除许多文件的应用程序可以通过创建自己的子目录并将该目录标记为已排除来实现。应用程序应该创建自己的排除目录，而不是排除系统定义的目录。

这两个文件系统属性都优于直接设置扩展属性的弃用方法。在 iOS 5.1 及更高版本上运行的所有应用程序都应使用这些属性从备份中排除数据。

以下是用于从iOS 5.1 及更高版本[的备份中排除文件的示例 Objective-C 代码：](https://developer.apple.com/library/content/qa/qa1719/index.html)

```
- (BOOL)addSkipBackupAttributeToItemAtPath:(NSString *) filePathString
{
    NSURL* URL= [NSURL fileURLWithPath: filePathString];
    assert([[NSFileManager defaultManager] fileExistsAtPath: [URL path]]);

    NSError *error = nil;
    BOOL success = [URL setResourceValue: [NSNumber numberWithBool: YES]
                                  forKey: NSURLIsExcludedFromBackupKey error: &error];
    if(!success){
        NSLog(@"Error excluding %@ from backup %@", [URL lastPathComponent], error);
    }
    return success;
}
```

以下是用于在 iOS 5.1 及更高版本上从备份中排除文件的示例 Swift 代码，请参阅[Swift 从 iCloud 备份中排除文件](https://bencoding.com/2017/02/20/swift-excluding-files-from-icloud-backup/)以获取更多信息：

```
enum ExcludeFileError: Error {
    case fileDoesNotExist
    case error(String)
}

func excludeFileFromBackup(filePath: URL) -> Result<Bool, ExcludeFileError> {
    var file = filePath

    do {
        if FileManager.default.fileExists(atPath: file.path) {
            var res = URLResourceValues()
            res.isExcludedFromBackup = true
            try file.setResourceValues(res)
            return .success(true)

        } else {
            return .failure(.fileDoesNotExist)
        }
    } catch {
        return .failure(.error("Error excluding \(file.lastPathComponent) from backup \(error)"))
    }
}
```

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_6)

为了测试备份，您显然需要先创建一个。创建 iOS 设备备份的最常见方法是使用 iTunes，它适用于 Windows、Linux，当然还有 macOS（直到 macOS Mojave）。通过 iTunes 创建备份时，您始终只能备份整个设备，而不能只选择一个应用程序。确保未设置 iTunes 中的“加密本地备份”选项，以便备份以明文形式存储在硬盘驱动器上。

> 从 macOS Catalina 开始，iTunes 不再可用。iOS 设备的管理（包括更新、备份和恢复）已移至 Finder 应用程序。如上所述，方法保持不变。

iOS设备备份完成后，需要获取备份的文件路径，每个OS的位置不同。Apple 官方文档将帮助您[找到 iPhone、iPad 和 iPod touch 的备份](https://support.apple.com/en-us/HT204215)。

当您想导航到 High Sierra 的备份文件夹时，您可以轻松地做到这一点。从 macOS Mojave 开始，您将收到以下错误（即使是 root）：

```
$ pwd
/Users/foo/Library/Application Support
$ ls -alh MobileSync
ls: MobileSync: Operation not permitted
```

这不是备份文件夹的权限问题，而是 macOS Mojave 中的一项新功能。[您可以按照OSXDaily](http://osxdaily.com/2018/10/09/fix-operation-not-permitted-terminal-error-macos/)上的说明授予对终端应用程序的完整磁盘访问权限，从而解决此问题。

在您可以访问该目录之前，您需要选择具有您设备的 UDID 的文件夹。查看“iOS 基本安全测试”一章中的“获取 iOS 设备的 UDID”部分，了解如何检索 UDID。

一旦你知道了 UDID，你就可以导航到这个目录，你会找到整个设备的完整备份，其中包括图片、应用程序数据以及设备上可能存储的任何内容。

查看备份文件和文件夹中的数据。目录和文件名的结构被混淆了，看起来像这样：

```
$ pwd
/Users/foo/Library/Application Support/MobileSync/Backup/416f01bd160932d2bf2f95f1f142bc29b1c62dcb/00
$ ls | head -n 3
000127b08898088a8a169b4f63b363a3adcf389b
0001fe89d0d03708d414b36bc6f706f567b08d66
000200a644d7d2c56eec5b89c1921dacbec83c3e
```

因此，浏览它并不简单，您不会在目录或文件名中找到任何要分析的应用程序的提示。您可以考虑使用[iMazing](https://imazing.com/)共享软件实用程序来提供帮助。使用 iMazing 执行设备备份并使用其内置的备份资源管理器轻松分析应用程序容器内容，包括原始路径和文件名。

如果没有 iMazing 或类似软件，您可能需要求助于使用 grep 来识别敏感数据。这不是最彻底的方法，但您可以尝试搜索在进行备份之前使用该应用程序时输入的敏感数据。例如：用户名、密码、信用卡数据、PII 或在应用上下文中被认为敏感的任何数据。

```
~/Library/Application Support/MobileSync/Backup/<UDID>
grep -iRn "password" .
```

如静态分析部分所述，您能够找到的任何敏感数据都应从备份中排除，使用钥匙串正确加密或首先不存储在设备上。

要确定备份是否已加密，您可以从位于备份目录根目录的文件“Manifest.plist”中检查名为“IsEncrypted”的密钥。以下示例显示了指示备份已加密的配置：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
...
 <key>Date</key>
 <date>2021-03-12T17:43:33Z</date>
 <key>IsEncrypted</key>
 <true/>
...
</plist>
```

如果您需要使用加密备份，[DinoSec 的 GitHub 存储库](https://github.com/dinosec/iphone-dataprotection/tree/master/python_scripts)中有一些 Python 脚本，例如 backup_tool.py 和 backup_passwd.py，它们将是一个很好的起点。但是，请注意，它们可能不适用于最新的 iTunes/Finder 版本，可能需要进行调整。

您还可以使用[iOSbackup](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#iosbackup)工具轻松地从密码加密的 iOS 备份中读取和提取文件。

#### 概念证明：使用篡改备份删除 UI 锁[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#proof-of-concept-removing-ui-lock-with-tampered-backup)

如前所述，敏感数据不仅限于用户数据和 PII。它也可以是影响应用程序行为、限制功能或启用安全控制的配置或设置文件。如果您查看开源比特币钱包应用程序[Bither](https://github.com/bither/bither-ios)，您会发现可以配置 PIN 码来锁定 UI。在几个简单的步骤之后，您将看到如何在非越狱设备上使用修改后的备份来绕过此 UI 锁定。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06d/bither_demo_enable_pin.png) ![img](https://mas.owasp.org/assets/Images/Chapters/0x06d/bither_demo_pin_screen.png)

启用 pin 后，使用 iMazing 执行设备备份：

1. **从可用**菜单下的列表中选择您的设备。
2. 单击顶部菜单选项**备份**。
3. 按照提示使用默认值完成备份。

接下来，您可以打开备份以查看目标应用程序中的应用程序容器文件：

1. 选择您的设备，然后单击右上角菜单中的**备份。**
2. 单击您创建的备份并选择**查看**。
3. **从Apps**目录导航到 Bither 应用程序。

此时您可以查看比太的所有备份内容。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06d/bither_demo_imazing_1.png)

您可以从这里开始解析文件以查找敏感数据。在屏幕截图中，您将看到`net.bither.plist`包含该`pin_code`属性的文件。要移除 UI 锁定限制，只需删除`pin_code`属性并保存更改即可。

从那里可以`net.bither.plist`使用 iMazing 的许可版本轻松地将修改后的版本恢复到设备上。

然而，免费的解决方法是在 iTunes/Finder 生成的模糊备份中找到 plist 文件。因此，使用配置了 Bither 的 PIN 码创建设备的备份。然后，使用前面描述的步骤，找到备份目录并 grep 查找“pin_code”，如下所示。

```
$ ~/Library/Application Support/MobileSync/Backup/<UDID>
$ grep -iRn "pin_code" .
Binary file ./13/135416dd5f251f9251e0f07206277586b7eac6f6 matches
```

您会看到一个二进制文件的匹配项，其名称经过混淆。这是你的`net.bither.plist`文件。继续并重命名文件，为其提供 plist 扩展名，以便 Xcode 可以轻松地为您打开它。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06d/bither_demo_plist.png)

再次`pin_code`从 plist 中删除该属性并保存您的更改。将文件重命名回原始名称（即，没有 plist 扩展名）并执行备份恢复。恢复完成后，您会看到 Bither 在启动时不再提示您输入 PIN 码。

## 测试自动生成的屏幕截图以获取敏感信息 (MSTG-STORAGE-9)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#testing-auto-generated-screenshots-for-sensitive-information-mstg-storage-9)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#overview_4)

制造商希望在应用程序启动或退出时为设备用户提供美观的效果，因此他们引入了在应用程序进入后台时保存屏幕截图的概念。此功能可能会带来安全风险，因为屏幕截图（可能显示敏感信息，如电子邮件或公司文档）被写入本地存储，在那里它们可以被具有沙箱绕过漏洞利用的流氓应用程序或窃取设备的人恢复。

如果应用程序进入后台后通过屏幕截图泄露任何敏感信息，则此测试用例将失败。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_7)

如果您有源代码，请搜索[`applicationDidEnterBackground`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1622997-applicationdidenterbackground)确定应用程序在后台运行前是否清理屏幕的方法。

以下是`overlayImage.png`在应用程序处于后台时使用默认背景图像 ( ) 覆盖当前视图的示例实现：

Swift:

```
private var backgroundImage: UIImageView?

func applicationDidEnterBackground(_ application: UIApplication) {
    let myBanner = UIImageView(image: #imageLiteral(resourceName: "overlayImage"))
    myBanner.frame = UIScreen.main.bounds
    backgroundImage = myBanner
    window?.addSubview(myBanner)
}

func applicationWillEnterForeground(_ application: UIApplication) {
    backgroundImage?.removeFromSuperview()
}
```

Objective-C：

```
@property (UIImageView *)backgroundImage;

- (void)applicationDidEnterBackground:(UIApplication *)application {
    UIImageView *myBanner = [[UIImageView alloc] initWithImage:@"overlayImage.png"];
    self.backgroundImage = myBanner;
    self.backgroundImage.bounds = UIScreen.mainScreen.bounds;
    [self.window addSubview:myBanner];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    [self.backgroundImage removeFromSuperview];
}
```

这会将背景图像设置为`overlayImage.png`每当应用程序处于后台时。它可以防止敏感数据泄漏，因为`overlayImage.png`它将始终覆盖当前视图。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_7)

您可以使用任何 iOS 设备（越狱与否）使用*可视化方法*快速验证此测试用例：

1. 导航到显示敏感信息（例如用户名、电子邮件地址或帐户详细信息）的应用程序屏幕。
2. 通过点击iOS 设备上的**主页**按钮使应用程序后台运行。
3. 确认默认图像显示为顶视图元素，而不是包含敏感信息的视图。

如果需要，您还可以在越狱设备或未越狱设备[上使用 Frida Gadget 重新打包应用程序](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#dynamic-analysis-on-non-jailbroken-devices)后，通过执行步骤 1 至 3 来收集证据。之后，通过[SSH](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#accessing-the-device-shell)或[其他方式](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#host-device-data-transfer)连接到 iOS 设备并导航到快照目录。每个 iOS 版本的位置可能不同，但通常位于应用程序的库目录中。在 iOS 14.5 上： `/var/mobile/Containers/Data/Application/$APP_ID/Library/SplashBoard/Snapshots/sceneID:$APP_NAME-default/`

该文件夹内的屏幕截图不应包含任何敏感信息。

## 测试内存中的敏感数据 (MSTG-STORAGE-10)[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#testing-memory-for-sensitive-data-mstg-storage-10)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#overview_5)

分析内存可以帮助开发人员找出应用程序崩溃等问题的根本原因。但是，它也可用于访问敏感数据。本节介绍如何检查进程的内存以进行数据泄露。

首先，确定存储在内存中的敏感信息。敏感资产很可能在某个时候被加载到内存中。目的是确保尽可能简短地公开此信息。

要调查应用程序的内存，首先要创建一个内存转储。或者，您可以使用调试器等工具实时分析内存。无论您使用哪种方法，这都是一个非常容易出错的过程，因为转储提供了已执行函数留下的数据，您可能会错过执行关键步骤。此外，在分析过程中忽略数据是很容易做到的，除非您知道您正在寻找的数据的足迹（无论是它的确切值还是它的格式）。例如，如果应用程序根据随机生成的对称密钥进行加密，除非您通过其他方式找到它的值，否则您不太可能在内存中发现该密钥。

因此，您最好从静态分析开始。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#static-analysis_8)

在查看源代码之前，检查文档和识别应用程序组件可提供可能公开数据的位置的概览。例如，虽然从后端接收到的敏感数据存在于最终模型对象中，但 HTTP 客户端或 XML 解析器中也可能存在多个副本。应尽快将所有这些副本从内存中删除。

了解应用程序的体系结构及其与操作系统的交互将帮助您识别根本不必在内存中公开的敏感信息。例如，假设您的应用程序从一台服务器接收数据并将其传输到另一台服务器而无需任何额外处理。该数据可以以加密形式接收和处理，从而防止通过内存暴露。

*但是，如果确实*需要通过内存公开敏感数据，请确保您的应用在尽可能短的时间内公开尽可能少的数据副本。换句话说，您希望基于原始和可变数据结构集中处理敏感数据。

这种数据结构使开发人员可以直接访问内存。确保此访问权限用于用零覆盖敏感数据和加密密钥。[Apple Secure Coding Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/SecurityDevelopmentChecklists/SecurityDevelopmentChecklists.html)建议在使用后将敏感数据清零，但未提供执行此操作的推荐方法。

首选数据类型的示例包括`char []`and `int []`，但不包括`NSString`or `String`。每当您尝试修改不可变对象（例如 a `String`）时，您实际上创建了一个副本并更改了该副本。考虑`NSMutableData`在 Swift/Objective-C 上用于存储机密，并使用[`resetBytes(in:)`方法](https://developer.apple.com/documentation/foundation/nsmutabledata/1415526-resetbytes)进行归零。另请参阅[清除机密数据的内存以](https://github.com/veorq/cryptocoding#clean-memory-of-secret-data/)供参考。

避免使用集合以外的 Swift 数据类型，无论它们是否被认为是可变的。许多 Swift 数据类型按值保存数据，而不是按引用。虽然这允许修改分配给简单类型（如`char`和）的内存`int`，但处理复杂类型（如`String`按值）涉及对象、结构或原始数组的隐藏层，其内存无法直接访问或修改。某些类型的用法可能看起来创建了一个可变数据对象（甚至被记录为这样做），但它们实际上创建了一个可变标识符（变量）而不是一个不可变标识符（常量）。例如，许多人认为以下结果会导致一个可变的`String`在 Swift 中，但这实际上是一个变量的示例，其复数值可以更改（替换，而不是就地修改）：

```
var str1 = "Goodbye"              // "Goodbye", base address:            0x0001039e8dd0
str1.append(" ")                 // "Goodbye ", base address:            0x608000064ae0
str1.append("cruel world!")      // "Goodbye cruel world", base address: 0x6080000338a0
str1.removeAll()                 // "", base address                    0x00010bd66180
```

请注意，基础值的基地址会随着每个字符串操作而变化。问题是：要安全地从内存中删除敏感信息，我们不想简单地更改变量的值；我们想要更改为当前值分配的内存的实际内容。Swift 不提供这样的功能。

另一方面，如果Swift 集合（`Array`、`Set`和）收集原始数据类型，例如or并且被定义为可变的（即，作为变量而不是常量），那么它们可能是可以接受的，在这种情况下，它们或多或少等同于原始数组（例如）。这些集合提供内存管理，如果集合需要将底层缓冲区复制到不同的位置以扩展它，这可能会导致内存中敏感数据的无法识别的副本。`Dictionary``char``int``char []`

使用可变的 Objective-C 数据类型，例如`NSMutableString`，也可能是可以接受的，但这些类型与 Swift 集合有相同的内存问题。使用 Objective-C 集合时要注意；它们通过引用保存数据，并且只允许使用 Objective-C 数据类型。因此，我们不是在寻找可变集合，而是在寻找引用可变对象的集合。

正如我们目前所见，使用 Swift 或 Objective-C 数据类型需要对语言实现有深入的了解。此外，在主要的 Swift 版本之间进行了一些核心重构，导致许多数据类型的行为与其他类型的行为不兼容。为避免这些问题，我们建议在需要从内存中安全擦除数据时使用原始数据类型。

不幸的是，很少有库和框架旨在允许覆盖敏感数据。甚至 Apple 也没有在官方 iOS SDK API 中考虑这个问题。例如，大多数用于数据转换（传递、序列化等）的 API 都对非原始数据类型进行操作。同样，无论您是否将某些内容标记`UITextField`为*安全文本输入*，它总是以`String`或的形式返回数据`NSString`。

总之，在对通过内存暴露的敏感数据进行静态分析时，您应该

- 尝试识别应用程序组件并映射数据的使用位置，
- 确保使用尽可能少的组件处理敏感数据，
- 一旦不再需要包含敏感数据的对象，请确保正确删除对象引用，
- 确保高度敏感的数据在不再需要时立即被覆盖，
- 不要通过不可变数据类型传递此类数据，例如`String`and `NSString`，
- 避免非原始数据类型（因为它们可能会留下数据），
- 在删除引用之前覆盖内存中的值，
- 注意第三方组件（库和框架）。拥有一个根据上述建议处理数据的公共 API 是一个很好的指标，表明开发人员考虑了此处讨论的问题。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#dynamic-analysis_8)

有多种方法和工具可用于动态测试 iOS 应用程序内存中的敏感数据。

#### 检索和分析内存转储[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#retrieving-and-analyzing-a-memory-dump)

无论您使用的是越狱设备还是非越狱设备，您都可以使用[objection](https://github.com/sensepost/objection)和[Fridump](https://github.com/Nightbringer21/fridump)转储应用程序的进程内存。您可以在“iOS 上的篡改和逆向工程”一章的“[内存转储](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#memory-dump)”部分找到有关此过程的详细说明。

内存转储后（例如转储到名为“内存”的文件），根据您要查找的数据的性质，您将需要一组不同的工具来处理和分析该内存转储。例如，如果您专注于字符串，那么执行命令`strings`或`rabin2 -zz`提取这些字符串可能就足够了。

```
# using strings
$ strings memory > strings.txt

# using rabin2
$ rabin2 -ZZ memory > strings.txt
```

在您最喜欢的编辑器中打开`strings.txt`并深入挖掘以识别敏感信息。

但是，如果您想检查其他类型的数据，您更愿意使用 radare2 及其搜索功能。`/?`有关详细信息和选项列表，请参阅 radare2 关于搜索命令 ( ) 的帮助。以下仅显示其中的一个子集：

```
$ r2 <name_of_your_dump_file>

[0x00000000]> /?
Usage: /[!bf] [arg]  Search stuff (see 'e??search' for options)
|Use io.va for searching in non virtual addressing spaces
| / foo\x00                    search for string 'foo\0'
| /c[ar]                       search for crypto materials
| /e /E.F/i                    match regular expression
| /i foo                       search for string 'foo' ignoring case
| /m[?][ebm] magicfile         search for magic, filesystems or binary headers
| /v[1248] value               look for an `cfg.bigendian` 32bit value
| /w foo                       search for wide string 'f\0o\0o\0'
| /x ff0033                    search for hex string
| /z min max                   search for strings of given size
...
```

#### Runtime(运行时)内存分析[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#runtime-memory-analysis)

通过使用[r2frida](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#r2frida)，您可以在Runtime(运行时)分析和检查应用程序的内存，而无需转储它。例如，您可以从 r2frida 运行之前的搜索命令并在内存中搜索字符串、十六进制值等。执行此操作时，请记住`\`在启动会话后在搜索命令（以及任何其他 r2frida 特定命令）前面加上反斜杠与`r2 frida://usb//<name_of_your_app>`。

有关更多信息、选项和方法，请参阅“ iOS 上的篡改和逆向工程”一章中的“[内存中搜索](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#in-memory-search)”部分。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#references)

- [#mandt] Tarjei Mandt、Mathew Solnik 和 David Wang，揭秘 Secure Enclave 处理器 - [https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave -处理器.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf)

### OWASP MASVS[¶](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#owasp-masvs)

- MSTG-STORAGE-1：“需要使用系统凭证存储设施来存储敏感数据，例如 PII、用户凭证或加密密钥。”
- MSTG-STORAGE-2：“不应将敏感数据存储在应用程序容器或系统凭证存储设施之外。”
- MSTG-STORAGE-3：“没有敏感数据写入应用程序日志。”
- MSTG-STORAGE-4：“除非是架构的必要部分，否则不会与第三方共享敏感数据。”
- MSTG-STORAGE-5：“键盘缓存在处理敏感数据的文本输入上被禁用。”
- MSTG-STORAGE-6：“没有敏感数据通过 IPC 机制公开。”
- MSTG-STORAGE-7：“没有敏感数据，例如密码或个人识别码，会通过用户界面暴露出来。”
- MSTG-STORAGE-8：“移动操作系统生成的备份中不包含任何敏感数据。”
- MSTG-STORAGE-9：“当移动到后台时，该应用程序会从视图中删除敏感数据。”
- MSTG-STORAGE-10：“该应用不会将敏感数据保存在内存中超过必要的时间，并且内存会在使用后明确清除。”
