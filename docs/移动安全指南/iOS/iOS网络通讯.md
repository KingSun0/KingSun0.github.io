# iOS网络通讯[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#ios-network-communication)

几乎每个 iOS 应用程序都充当一个或多个远程服务的客户端。由于这种网络通信通常发生在公共 Wi-Fi 等不受信任的网络上，因此基于经典网络的攻击成为一个潜在问题。

大多数现代移动应用程序都使用基于 HTTP 的 Web 服务的变体，因为这些协议已得到充分记录和支持。

## 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#overview)

### iOS 应用传输安全[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#ios-app-transport-security)

从 iOS 9 开始，Apple 引入了[App Transport Security (ATS)](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity)，这是一组由操作系统强制执行的安全检查，用于使用[URL 加载系统](https://developer.apple.com/documentation/foundation/url_loading_system)（通常通过`URLSession`）建立的连接始终使用 HTTPS。应用程序应遵循[Apple 的最佳做法](https://developer.apple.com/news/?id=jxky8h89)以正确保护其连接。

> [观看 Apple WWDC 2015 中的 ATS 介绍视频](https://developer.apple.com/videos/play/wwdc2015/711/?time=321)。

ATS 执行默认的服务器信任评估并需要最低限度的安全要求。

**默认服务器信任评估：**

当应用程序连接到远程服务器时，服务器使用 X.509 数字证书提供其身份。ATS 默认服务器信任评估包括验证证书：

- 没过期。
- 具有与服务器的 DNS 名称相匹配的名称。
- 具有有效（未被篡改）的数字签名，并且可以追溯到[操作系统信任库](https://support.apple.com/en-us/HT209143)中包含的受信任的证书颁发机构 (CA) ，或者由用户或系统管理员安装在客户端上。

**连接的最低安全要求：**

ATS 将阻止进一步未能满足一组[最低安全要求](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138464)的连接，包括：

- TLS 版本 1.2 或更高版本。
- 使用 AES-128 或 AES-256 进行数据加密。
- 证书必须使用 RSA 密钥（2048 位或更高）或 ECC 密钥（256 位或更高）签名。
- 证书的指纹必须使用 SHA-256 或更高版本。
- 该链接必须通过椭圆曲线 Diffie-Hellman 临时 (ECDHE) 密钥交换支持完全前向保密 (PFS)。

**证书有效性检查：**

[根据苹果](https://support.apple.com/en-gb/guide/security/sec100a75d12/web#sec8b087b1f7)，“评估 TLS 证书的可信状态是根据 RFC 5280 中规定的既定行业标准执行的，并结合了新兴标准，例如 RFC 6962（证书透明度）。在 iOS 11 或更高版本中，Apple 设备会定期更新包含当前已撤销和受限证书列表。该列表是从证书撤销列表 (CRL) 汇总而来的，这些列表由 Apple 信任的每个内置根证书颁发机构及其下属 CA 颁发者发布。该列表还可能包括 Apple 自行决定的其他限制。每当使用网络 API 功能建立安全连接时，都会查阅此信息。如果来自 CA 的吊销证书太多而无法单独列出，信任评估可能需要在线证书状态响应（OCSP），如果响应不可用，信任评估将失败。”

#### ATS 什么时候不适用？[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#when-does-ats-not-apply)

- **使用较低级别的 API 时：** ATS 仅适用于[URL 加载系统](https://developer.apple.com/documentation/foundation/url_loading_system)，包括[URLSession](https://developer.apple.com/reference/foundation/urlsession)和位于它们之上的 API。它不适用于使用较低级别 API（如 BSD 套接字）的应用程序，包括那些在这些较低级别 API 之上实现 TLS 的应用程序（请参阅存档的 Apple 开发人员文档中的[“在 Apple 框架中使用 ATS”部分）。](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW55)
- **当连接到 IP 地址、不合格的域名或本地主机时：** ATS 仅适用于与公共主机名建立的连接（请参阅存档的 Apple 开发人员文档中的[“ATS 用于远程和本地连接的可用性”部分）。](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW54)系统不为以下连接提供 ATS 保护：
- 互联网协议 (IP) 地址
- 不合格的主机名
- 使用 .local 顶级域 (TLD) 的本地主机
- **包含 ATS Exceptions 时：如果应用使用 ATS 兼容 API，它仍然可以使用**[ATS Exceptions](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#ats-exceptions)为特定场景禁用 ATS 。

学到更多：

- [“具有专用网络的 ATS 和 iOS 企业应用程序”](https://developer.apple.com/forums/thread/79662)
- [“ATS 和本地 IP 地址”](https://developer.apple.com/forums/thread/66417)
- [“ATS 对应用使用第三方库的影响”](https://developer.apple.com/forums/thread/69197)
- [“ATS 和 SSL 固定/自己的 CA”](https://developer.apple.com/forums/thread/53314)

#### ATS 例外情况[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#ats-exceptions)

可以通过在密钥`Info.plist`下的文件中配置例外来禁用 ATS 限制。`NSAppTransportSecurity`这些例外可适用于：

- 允许不安全的连接（HTTP），
- 降低最低 TLS 版本，
- 禁用完美前向保密 (PFS) 或
- 允许连接到本地域。

ATS 例外可以在全球或每个域的基础上应用。该应用程序可以全局禁用 ATS，但选择加入个别域。Apple Developer 文档中的以下清单显示了[`NSAppTransportSecurity`](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/plist/info/NSAppTransportSecurity)字典的结构。

```
NSAppTransportSecurity : Dictionary {
    NSAllowsArbitraryLoads : Boolean
    NSAllowsArbitraryLoadsForMedia : Boolean
    NSAllowsArbitraryLoadsInWebContent : Boolean
    NSAllowsLocalNetworking : Boolean
    NSExceptionDomains : Dictionary {
        <domain-name-string> : Dictionary {
            NSIncludesSubdomains : Boolean
            NSExceptionAllowsInsecureHTTPLoads : Boolean
            NSExceptionMinimumTLSVersion : String
            NSExceptionRequiresForwardSecrecy : Boolean   // Default value is YES
            NSRequiresCertificateTransparency : Boolean
        }
    }
}
```

资料来源：[Apple 开发者文档](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html)。

下表总结了全球 ATS 例外情况。有关这些异常的更多信息，请参阅[官方 Apple 开发人员文档中的表 2](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW34)。

| 钥匙                                 | 描述                                                        |
| :----------------------------------- | :---------------------------------------------------------- |
| `NSAllowsArbitraryLoads`             | 全局禁用 ATS 限制，但下指定的个别域除外`NSExceptionDomains` |
| `NSAllowsArbitraryLoadsInWebContent` | 对从 Web 视图建立的所有连接禁用 ATS 限制                    |
| `NSAllowsLocalNetworking`            | 允许连接到不合格的域名和 .local 域                          |
| `NSAllowsArbitraryLoadsForMedia`     | 对通过 AV Foundations 框架加载的媒体禁用所有 ATS 限制       |

下表总结了每个域的 ATS 例外情况。有关这些异常的更多信息，请参阅[Apple 官方开发人员文档中的表 3](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW44)。

| 钥匙                                 | 描述                                      |
| :----------------------------------- | :---------------------------------------- |
| `NSIncludesSubdomains`               | 指示 ATS 例外是否应应用于指定域的子域     |
| `NSExceptionAllowsInsecureHTTPLoads` | 允许 HTTP 连接到命名域，但不影响 TLS 要求 |
| `NSExceptionMinimumTLSVersion`       | 允许连接到 TLS 版本低于 1.2 的服务器      |
| `NSExceptionRequiresForwardSecrecy`  | 禁用完全前向保密 (PFS)                    |

**证明异常：**

从 2017 年 1 月 1 日开始，如果定义了以下 ATS 异常之一，Apple App Store 审核[需要提供理由。](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036)

- `NSAllowsArbitraryLoads`
- `NSAllowsArbitraryLoadsForMedia`
- `NSAllowsArbitraryLoadsInWebContent`
- `NSExceptionAllowsInsecureHTTPLoads`
- `NSExceptionMinimumTLSVersion`

这必须仔细修改以确定它是否确实是应用程序预期目的的一部分。Apple 警告异常会降低应用程序的安全性，并建议仅在需要时配置异常，并且在遇到 ATS 故障时**更喜欢服务器修复。**

**例子：**

在以下示例中，ATS 是全局启用的（没有全局定义），但为域（及其子域）**明确设置**`NSAllowsArbitraryLoads`了一个例外。考虑到该域归应用程序开发人员所有，并且有适当的理由可以接受此异常，因为它为所有其他域保留了 ATS 的所有好处。但是，始终最好按照上面的指示修复服务器。`example.com`

```
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

有关 ATS 异常的更多信息，请参阅[Apple 开发人员文档](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138482)中的文章“防止不安全的网络连接”和[ATS 上的博客文章](https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/)中的“仅在需要时配置异常；首选服务器修复”部分。

### iOS 网络 API[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#ios-network-apis)

自 iOS 12.0 起，[网络](https://developer.apple.com/documentation/network)框架和[`URLSession`](https://developer.apple.com/documentation/foundation/urlsession)类提供了异步和同步加载网络和 URL 请求的方法。旧的 iOS 版本可以使用[Sockets API](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/UsingSocketsandSocketStreams.html)。

#### 网络框架[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#network-framework)

该`Network`框架于 2018 年在[Apple 全球开发者大会 (WWDC)](https://developer.apple.com/videos/play/wwdc2018/715)上推出，是 Sockets API 的替代品。这个低级网络框架提供类来发送和接收具有内置动态网络、安全和性能支持的数据。

如果使用参数，则默认情况下在`Network`框架中启用 TLS 1.3 `using: .tls`。它是传统[安全传输](https://developer.apple.com/documentation/security/secure_transport)框架的首选选项。

#### 网址会话[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#urlsession)

`URLSession`建立在`Network`框架之上并使用相同的传输服务。如果端点是 HTTPS，该类还默认使用 TLS 1.3。

**`URLSession`应该用于 HTTP 和 HTTPS 连接，而不是`Network`直接使用框架。**该类`URLSession`本身支持这两种 URL 方案，并针对此类连接进行了优化。它需要更少的样板代码，减少出错的可能性并确保默认情况下的安全连接。`Network`只有在有低级和/或高级网络要求时才应使用该框架。

Apple 官方文档包括使用`Network`框架[实现 netcat](https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework)和`URLSession`将[网站数据提取到内存](https://developer.apple.com/documentation/foundation/url_loading_system/fetching_website_data_into_memory)中的示例。

## 在网络上测试数据加密 (MSTG-NETWORK-1)[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-data-encryption-on-the-network-mstg-network-1)

所有提出的案例都必须作为一个整体仔细分析。例如，即使应用程序在其 Info.plist 中不允许明文流量，它实际上可能仍在发送 HTTP 流量。如果它使用低级 API（ATS 被忽略）或配置错误的跨平台框架，则可能会出现这种情况。

> 重要提示：您应该将这些测试应用于应用程序主代码，但也应用于应用程序中嵌入的任何应用程序扩展、框架或 Watch 应用程序。

有关详细信息，请参阅 Apple 开发人员文档中的文章[“防止不安全的网络连接”](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)和[“微调您的应用程序传输安全设置”](https://developer.apple.com/news/?id=jxky8h89)。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#static-analysis)

#### 通过安全协议测试网络请求[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-network-requests-over-secure-protocols)

首先，您应该识别源代码中的所有网络请求，并确保没有使用纯 HTTP URL。确保通过使用[`URLSession`](https://developer.apple.com/documentation/foundation/urlsession)（使用 iOS 的标准[URL 加载系统](https://developer.apple.com/documentation/foundation/url_loading_system)）或[`Network`](https://developer.apple.com/documentation/network)（使用 TLS 的套接字级通信以及对 TCP 和 UDP 的访问）通过安全通道发送敏感信息。

#### 检查低级网络 API 的使用情况[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#check-for-low-level-networking-api-usage)

识别应用程序使用的网络 API 并查看它是否使用任何低级网络 API。

> **Apple 建议：在您的应用程序中首选高级框架**：“ATS 不适用于您的应用程序对网络框架或 CFNetwork 等较低级别网络接口的调用。在这些情况下，您负责确保连接的安全性。您可以通过这种方式构建安全连接，但错误既容易发生又代价高昂。依赖 URL 加载系统通常是最安全的”（请参阅[源代码](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)）。

如果该应用程序使用任何低级 API（例如[`Network`](https://developer.apple.com/documentation/network)或[`CFNetwork`](https://developer.apple.com/documentation/cfnetwork)），您应该仔细调查它们是否被安全使用。对于使用跨平台框架（例如 Flutter、Xamarin 等）和第三方框架（例如 Alamofire）的应用程序，您应该分析它们是否根据最佳实践安全地配置和使用。

确保该应用程序：

- 在执行服务器信任评估时验证质询类型以及主机名和凭据。
- 不会忽略 TLS 错误。
- 不使用任何不安全[的 TLS 配置（请参阅“测试 TLS 设置 (MSTG-NETWORK-2)”](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-the-tls-settings-mstg-network-2)）

这些检查是定向的，我们无法命名特定的 API，因为每个应用程序可能使用不同的框架。请在检查代码时使用此信息作为参考。

#### 测试明文流量[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-for-cleartext-traffic)

确保该应用不允许明文 HTTP 流量。由于 iOS 9.0 明文 HTTP 流量在默认情况下被阻止（由于应用程序传输安全 (ATS)），但应用程序仍然可以通过多种方式发送它：

- 通过在`NSAllowsArbitraryLoads`应用`true`程序的.`YES``NSAppTransportSecurity``Info.plist`
- [检索`Info.plist`](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#the-infoplist-file)
- 检查`NSAllowsArbitraryLoads`是否没有为任何域设置为`true`全局。
- 如果应用程序在 WebViews 中打开第三方网站，则从 iOS 10 开始`NSAllowsArbitraryLoadsInWebContent`可用于禁用对 Web 视图中加载的内容的 ATS 限制。

> **Apple 警告：**禁用 ATS 意味着允许不安全的 HTTP 连接。还允许 HTTPS 连接，并且仍受默认服务器信任评估的约束。但是，扩展的安全检查——例如要求最低传输层安全 (TLS) 协议版本——被禁用。如果没有 ATS，您也可以随意放宽默认的服务器信任要求，如[“执行手动服务器信任身份验证”](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication)中所述。

以下代码段显示了一个应用程序在全球范围内禁用 ATS 限制的**易受攻击示例**。

```
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

应在考虑应用程序上下文的情况下检查 ATS。应用程序可能*必须*定义 ATS 异常以实现其预期目的。例如，[Firefox iOS 应用程序已全局禁用 ATS](https://github.com/mozilla-mobile/firefox-ios/blob/v97.0/Client/Info.plist#L82)。此异常是可以接受的，否则应用程序将无法连接到任何不具备所有 ATS 要求的 HTTP 网站。在某些情况下，应用程序可能会全局禁用 ATS，但会为某些域启用它，例如安全加载元数据或仍然允许安全登录。

ATS 应该为此包含一个[理由字符串](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036)（例如“应用程序必须连接到由另一个不支持安全连接的实体管理的服务器。”）。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#dynamic-analysis)

拦截测试应用程序的传入和传出网络流量，并确保此流量已加密。您可以通过以下任一方式拦截网络流量：

- [使用OWASP ZAP](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#owasp-zap)或[Burp Suite](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#burp-suite)等拦截代理捕获所有 HTTP(S) 和 Websocket 流量，并确保所有请求都是通过 HTTPS 而不是 HTTP 发出的。
- Burp 和 OWASP ZAP 等拦截代理将仅显示 HTTP(S) 流量。但是，您可以使用 Burp 插件（例如[Burp-non-HTTP-Extension）](https://github.com/summitt/Burp-Non-HTTP-Extension)或工具[mitm-relay](https://github.com/jrmdev/mitm_relay)来解码和可视化通过 XMPP 和其他协议进行的通信。

> 由于证书固定，某些应用程序可能无法与 Burp 和 OWASP ZAP 等代理一起使用。在这种情况下，请检查[“测试自定义证书存储和证书固定”](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-custom-certificate-stores-and-certificate-pinning-mstg-network-4)。

有关更多详细信息，请参阅：

- [“测试网络通信”](https://mas.owasp.org/MASTG/General/0x04f-Testing-Network-Communication/#intercepting-traffic-on-the-network-layer)一章中的“在网络层拦截流量”
- [iOS 基本安全测试](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#setting-up-a-network-testing-environment)一章中的“设置网络测试环境”

## 测试 TLS 设置 (MSTG-NETWORK-2)[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-the-tls-settings-mstg-network-2)

请记住[检查相应的理由](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036)，以放弃它可能是应用程序预期目的的一部分。

可以验证在与特定端点通信时可以使用哪些 ATS 设置。`nscurl`在 macOS 上，可以使用命令行实用程序。将针对指定端点执行和验证不同设置的排列。如果默认的 ATS 安全连接测试通过，则可以在其默认安全配置中使用 ATS。如果nscurl输出有任何失败，请更改TLS的服务器端配置，使服务器端更安全，而不是削弱客户端ATS中的配置。[有关更多详细信息，请参阅Apple 开发人员文档](https://developer.apple.com/documentation/security/preventing_insecure_network_connections/identifying_the_source_of_blocked_connections)中的文章“识别被阻止连接的来源” 。

[有关详细信息，请参阅测试网络通信](https://mas.owasp.org/MASTG/General/0x04f-Testing-Network-Communication/#verifying-the-tls-settings-mstg-network-2)一章中的“验证 TLS 设置”部分。

## 测试端点身份验证 (MSTG-NETWORK-3)[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-endpoint-identity-verification-mstg-network-3)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#overview_1)

ATS 实施扩展安全检查，以补充传输层安全 (TLS) 协议规定的默认服务器信任评估。您应该测试应用程序是否放宽了 ATS 限制，因为这会降低应用程序的安全性。在添加 ATS 异常之前，应用程序应该首选其他方法来提高服务器安全性。

[Apple Developer Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)解释了应用程序可以用来`URLSession`自动处理服务器信任评估。但是，应用程序也可以自定义该过程，例如它们可以：

- 绕过或自定义证书过期。
- 放松/扩展信任：接受否则会被系统拒绝的服务器凭据，例如使用应用程序中嵌入的自签名证书与开发服务器建立安全连接。
- 加强信任：拒绝系统接受的凭据（请参阅[“测试自定义证书存储和证书固定”](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-custom-certificate-stores-and-certificate-pinning-mstg-network-4)）。
- 等等

![img](https://mas.owasp.org/assets/Images/Chapters/0x06g/manual-server-trust-evaluation.png)

参考：

- [防止不安全的网络连接](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)
- [执行手动服务器信任验证](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication)
- [证书、密钥和信任服务](https://developer.apple.com/documentation/security/certificate_key_and_trust_services)

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#static-analysis_1)

在本节中，我们将介绍几种静态分析检查。但是，我们强烈建议使用动态分析来支持它们。如果您没有源代码或应用程序难以逆向工程，拥有可靠的动态分析策略绝对有帮助。在那种情况下，您将不知道该应用程序使用的是低级 API 还是高级 API，但您仍然可以针对不同的信任评估场景进行测试（例如“该应用程序是否接受自签名证书？”）。

#### 检查操作系统版本[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#check-the-os-version)

如果应用程序链接到早于 iOS 9.0 的 SDK，则无论应用程序在哪个版本的操作系统上运行，ATS 都会被禁用。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#dynamic-analysis_1)

我们的测试方法是逐步放宽SSL握手协商的安全性，检查启用了哪些安全机制。

1. 将 Burp 设置为代理后，确保没有证书添加到信任存储区（**设置**->**常规**->**配置文件**）并且 SSL Kill Switch 等工具已停用。启动您的应用程序并检查您是否可以在 Burp 中看到流量。任何失败都将在“警报”选项卡下报告。如果您可以看到流量，则意味着根本没有执行证书验证。但是，如果您看不到任何流量并且有关于 SSL 握手失败的信息，请执行下一点。
2. 现在，安装 Burp 证书，如[Burp 的用户文档](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device)中所述。如果握手成功并且您可以在 Burp 中看到流量，则意味着证书已针对设备的信任库进行了验证，但未执行固定。

如果执行上一步中的指令不会导致流量被代理，则可能意味着证书固定实际上已实施并且所有安全措施都已到位。但是，您仍然需要绕过固定以测试应用程序。有关这方面的更多信息，请参阅[“绕过证书固定”部分。](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#bypassing-certificate-pinning)

## 测试自定义证书存储和证书固定 (MSTG-NETWORK-4)[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#testing-custom-certificate-stores-and-certificate-pinning-mstg-network-4)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#overview_2)

此测试验证应用程序是否正确实施身份锁定（证书或公钥锁定）。

有关详细信息，请参阅一般章节[“移动应用程序网络通信”](https://mas.owasp.org/MASTG/General/0x04f-Testing-Network-Communication/#identity-pinning)中的“身份固定”部分。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#static-analysis_2)

验证服务器证书是否已固定。根据服务器提供的证书树，可以在各个级别上实现固定：

1. 在应用程序包中包含服务器证书并对每个连接执行验证。每当更新服务器上的证书时，这都需要更新机制。
2. 将证书颁发者限制为例如一个实体并将中间 CA 的公钥捆绑到应用程序中。通过这种方式，我们限制了攻击面并获得了有效的证书。
3. 拥有和管理您自己的 PKI。该应用程序将包含中间 CA 的公钥。这样可以避免每次更改服务器上的证书时都更新应用程序，例如由于过期。请注意，使用您自己的 CA 会导致证书自行签名。

`Info.plist`Apple 推荐的最新方法是在 App Transport Security Settings 下的文件中指定一个固定的 CA 公钥。[您可以在他们的文章Identity Pinning: How to configure server certificates for your app](https://developer.apple.com/news/?id=g9ejcf8y)中找到示例。

另一种常见的做法是使用 的[`connection:willSendRequestForAuthenticationChallenge:`](https://developer.apple.com/documentation/foundation/nsurlconnectiondelegate/1414078-connection?language=objc)方法`NSURLConnectionDelegate`检查服务器提供的证书是否有效，是否与应用程序中存储的证书相匹配。[您可以在HTTPS 服务器信任评估](https://developer.apple.com/library/archive/technotes/tn2232/_index.html#//apple_ref/doc/uid/DTS40012884-CH1-SECNSURLCONNECTION)技术说明中找到更多详细信息。

以下第三方库包含固定功能：

- [TrustKit](https://github.com/datatheorem/TrustKit)：在这里你可以通过在你的 Info.plist 中设置公钥散列来固定或者在字典中提供散列。有关详细信息，请参阅他们的自述文件。
- [AlamoFire](https://github.com/Alamofire/Alamofire)：在这里您可以定义一个`ServerTrustPolicy`每个域，您可以为其定义一个`PinnedCertificatesTrustEvaluator`. 有关详细信息，请参阅其[文档。](https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#security)
- [AFNetworking](https://github.com/AFNetworking/AFNetworking)：在这里你可以设置一个`AFSecurityPolicy`来配置你的固定。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#dynamic-analysis_2)

#### 服务器证书固定[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#server-certificate-pinning)

按照[“测试端点识别验证 > 动态分析 > 服务器证书验证”](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#server-certificate-validation)中的说明进行操作。如果这样做不会导致流量被代理，则可能意味着实际上已实施证书固定并且所有安全措施都已到位。所有域都会发生同样的情况吗？

作为快速冒烟测试，您可以尝试使用[objection](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#objection)绕过证书固定，如[“绕过证书固定”](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#bypassing-certificate-pinning)中所述。被objectionHook的固定相关 API 应该出现在objection的输出中。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/ios_ssl_pinning_bypass.png)

但是，请记住：

- API 可能不完整。
- 如果没有任何东西被钩住，那并不一定意味着该应用程序没有实现固定。

[在这两种情况下，应用程序或其某些组件可能会以 objection 支持](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts)的方式实现自定义固定。请查看静态分析部分以了解具体的固定指标和更深入的测试。

#### 客户端证书验证[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#client-certificate-validation)

一些应用程序使用 mTLS（双向 TLS），这意味着应用程序验证服务器的证书，服务器验证客户端的证书。**如果 Burp Alerts**选项卡中显示客户端未能协商连接的错误，您会注意到这一点。

有几件事值得注意：

1. 客户端证书包含将用于密钥交换的私钥。
2. 通常证书还需要密码才能使用（解密）它。
3. 证书可以存储在二进制文件本身、数据目录或钥匙串中。

使用 mTLS 的最常见和不正确的方式是将客户端证书存储在应用程序包中并对密码进行硬编码。这显然不会带来太多安全性，因为所有客户端将共享同一个证书。

存储证书（可能还有密码）的第二种方法是使用钥匙串。首次登录时，应用程序应下载个人证书并将其安全地存储在钥匙串中。

有时应用程序有一个硬编码的证书，并在第一次登录时使用它，然后下载个人证书。在这种情况下，请检查是否仍可以使用“通用”证书连接到服务器。

从应用程序中提取证书后（例如使用 Frida），将其作为客户端证书添加到 Burp 中，您将能够拦截流量。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#references)

### OWASP MASVS[¶](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/#owasp-masvs)

- MSTG-NETWORK-1：“数据在网络上使用 TLS 加密。整个应用程序始终使用安全通道。”
- MSTG-NETWORK-2：“TLS 设置符合当前最佳实践，或者如果移动操作系统不支持推荐标准，则尽可能接近。”
- MSTG-NETWORK-3：“应用程序在建立安全通道时验证远程端点的 X.509 证书。只接受由受信任的 CA 签名的证书。”
- MSTG-NETWORK-4：“该应用程序要么使用自己的证书存储，要么固定端点证书或公钥，随后不会与提供不同证书或密钥的端点建立连接，即使由受信任的 CA 签名也是如此。”
