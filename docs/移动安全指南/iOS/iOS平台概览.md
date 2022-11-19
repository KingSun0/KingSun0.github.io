# iOS 平台概览[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#ios-platform-overview)

iOS 是一种移动操作系统，支持 Apple 移动设备，包括 iPhone、iPad 和 iPod Touch。它也是 Apple tvOS 的基础，它继承了 iOS 的许多功能。本节从架构的角度介绍iOS平台。讨论了以下五个关键领域：

1. iOS安全架构
2. iOS应用程序结构
3. 进程间通信 (IPC)
4. iOS应用发布
5. iOS 应用程序攻击面

与 Apple 桌面操作系统 macOS（以前称为 OS X）一样，iOS 也是基于 Darwin，这是 Apple 开发的开源 Unix 操作系统。Darwin 的内核是 XNU（“X is Not Unix”），一个结合了 Mach 和 FreeBSD 内核组件的混合内核。

但是，与桌面应用程序相比，iOS 应用程序在更受限制的环境中运行。iOS 应用程序在文件系统级别相互隔离，并且在系统 API 访问方面受到显着限制。

为了保护用户免受恶意应用程序的侵害，Apple 限制和控制对允许在 iOS 设备上运行的应用程序的访问。Apple 的 App Store 是唯一的官方应用程序分发平台。开发人员可以在那里提供他们的应用程序，消费者可以购买、下载和安装应用程序。这种分发方式与 Android 不同，Android 支持多个应用商店和侧载（在不使用官方 App Store 的情况下在 iOS 设备上安装应用）。[在 iOS 中，sideloading 通常是指通过 USB 安装应用程序的方法，尽管在Apple Developer Enterprise Program](https://developer.apple.com/programs/enterprise/)下还有其他不使用 App Store 的企业 iOS 应用程序分发方法。

过去，只有通过越狱或复杂的解决方法才能实现侧载。使用 iOS 9 或更高版本，可以[通过 Xcode 侧载](https://www.igeeksblog.com/how-to-sideload-apps-on-iphone-ipad-in-ios-10/)。

iOS 应用程序通过 Apple 的 iOS 沙箱（以前称为 Seatbelt）相互隔离，这是一种强制访问控制 (MAC) 机制，描述了应用程序可以访问和不能访问的资源。与 Android 广泛的 Binder IPC 设施相比，iOS 提供的 IPC（进程间通信）选项非常少，从而最大限度地减少了潜在的攻击面。

统一的硬件和紧密的硬件/软件集成创造了另一个安全优势。每个 iOS 设备都提供安全功能，例如安全启动、硬件支持的钥匙串和文件系统加密（在 iOS 中称为数据保护）。iOS 更新通常会很快向大部分用户推出，从而减少了支持旧的、未受保护的 iOS 版本的需要。

尽管 iOS 具有众多优势，但 iOS 应用程序开发人员仍然需要担心安全问题。数据保护、Keychain、Touch ID/Face ID 身份验证和网络安全仍然存在很大的错误余地。在接下来的章节中，我们将描述 iOS 安全架构，解释基本的安全测试方法，并提供逆向工程方法。

## iOS 安全架构[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#ios-security-architecture)

Apple 在 iOS 安全指南中正式记录的[iOS 安全架构包含六个核心功能。](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)Apple 针对每个主要 iOS 版本更新了本安全指南：

- 硬件安全
- 安全启动
- 代码签名
- 沙盒
- 加密和数据保护
- 一般漏洞利用缓解措施

![img](https://mas.owasp.org/assets/Images/Chapters/0x06a/iOS_Security_Architecture.png)

### 硬件安全[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#hardware-security)

iOS 安全架构充分利用了基于硬件的安全功能来增强整体性能。每个 iOS 设备都带有两个内置的高级加密标准 (AES) 256 位密钥。设备的唯一 ID (UID) 和设备组 ID (GID) 是 AES 256 位密钥，在制造过程中融合 (UID) 或编译 (GID) 到应用程序处理器 (AP) 和 Secure Enclave 处理器 (SEP) 中。没有直接的方法可以使用软件或调试接口（例如 JTAG）来读取这些密钥。加密和解密操作由对这些密钥具有独占访问权限的硬件 AES Crypto引擎执行。

GID 是一类设备中所有处理器共享的值，用于防止篡改固件文件和其他与用户私人数据不直接相关的加密任务。UID 对每个设备都是唯一的，用于保护用于设备级文件系统加密的密钥层次结构。由于在制造过程中未记录 UID，因此即使是 Apple 也无法恢复特定设备的文件加密密钥。

为允许安全删除闪存上的敏感数据，iOS 设备包含一项称为[Effaceable Storage](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)的功能。此功能提供对存储技术的直接低级别访问，从而可以安全地擦除选定的块。

### 安全启动[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#secure-boot)

当 iOS 设备开机时，它会从称为引导 ROM 的只读存储器中读取初始指令，引导系统。Boot ROM 包含不可变代码和 Apple Root CA，它在制造过程中蚀刻到硅芯片中，从而创建信任根。接下来，Boot ROM 确保 LLB（低级引导加载程序）的签名正确，LLB 检查 iBoot 引导加载程序的签名是否也正确。签名通过验证后，iBoot 会检查下一个启动阶段的签名，即 iOS 内核。如果这些步骤中的任何一个失败，启动过程将立即终止，设备将进入恢复模式并显示[恢复屏幕](https://support.apple.com/en-us/HT203122). 但是，如果引导 ROM 加载失败，设备将进入一种称为设备固件升级 (DFU) 的特殊低级恢复模式。这是将设备恢复到其原始状态的最后手段。在这种模式下，设备不会显示任何活动迹象；即，它的屏幕不会显示任何内容。

整个过程称为“安全启动链”。其目的在于验证启动过程的完整性，确保系统及其组件由 Apple 编写和分发。安全启动链由内核、引导加载程序、内核扩展和基带固件组成。

### 代码签名[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#code-signing)

Apple 实施了精心设计的 DRM 系统，以确保只有 Apple 批准的代码才能在其设备上运行，即由 Apple 签名的代码。换句话说，除非 Apple 明确允许，否则您将无法在未越狱的 iOS 设备上运行任何代码。最终用户应该只能通过官方 Apple 的 App Store 安装应用程序。由于这个原因（以及其他原因），iOS 被[比作水晶监狱](https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms)。

部署和运行应用程序需要开发人员配置文件和 Apple 签名的证书。开发人员需要在 Apple 注册，加入[Apple Developer Program](https://developer.apple.com/support/compare-memberships/)并支付年度订阅费，以获得全方位的开发和部署可能性。还有一个免费的开发者帐户，允许您通过侧载编译和部署应用程序（但不能在 App Store 中分发它们）。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06a/code_signing.png)

根据[存档的 Apple 开发者文档](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html#//apple_ref/doc/uid/TP40005929-CH3-SW3)，代码签名由三部分组成：

- 印章。这是代码各个部分的校验和或哈希的集合，由代码签名软件创建。印章可在验证时使用以检测更改。
- 数字签名。代码签名软件使用签名者的身份对印章进行加密以创建数字签名。这保证了印章的完整性。
- 代码要求。这些是管理代码签名验证的规则。根据目标，一些是验证者固有的，而另一些是由签名者指定并与其余代码密封的。

学到更多：

- [代码签名指南（存档的 Apple 开发者文档）](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [代码签名（Apple 开发者文档）](https://developer.apple.com/support/code-signing/)
- [揭秘 iOS 代码签名](https://medium.com/csit-tech-blog/demystifying-ios-code-signature-309d52c2ff1d)

### 加密和数据保护[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#encryption-and-data-protection)

*FairPlay 代码加密*适用于从 App Store 下载的应用程序。FairPlay 是在购买多媒体内容时作为 DRM 开发的。最初，FairPlay 加密应用于 MPEG 和 QuickTime 流，但同样的基本概念也可以应用于可执行文件。基本思路如下：一旦您注册了一个新的 Apple 用户帐户或 Apple ID，就会创建一个公钥/私钥对并将其分配给您的帐户。私钥安全地存储在您的设备上。这意味着 FairPlay 加密代码只能在与您的帐户关联的设备上解密。反向 FairPlay 加密通常通过在设备上运行应用程序，然后从内存中转储解密代码来获得（另请参阅“iOS 上的基本安全测试”）。

自 iPhone 3GS 发布以来，Apple 就在其 iOS 设备的硬件和固件中内置了加密功能。每个设备都有一个专用的基于硬件的加密引擎，提供 AES 256 位加密和 SHA-1 散列算法的实现。此外，每台设备的硬件中都有一个内置的唯一标识符 (UID)，其 AES 256 位密钥融合到应用程序处理器中。这个 UID 是唯一的，没有记录在别处。在撰写本文时，无论是软件还是固件都无法直接读取 UID。由于密钥被烧入硅片，因此无法被篡改或绕过。只有加密引擎可以访问它。

将加密构建到物理架构中使其成为默认安全功能，可以加密存储在 iOS 设备上的所有数据。因此，数据保护是在软件层面实施的，并与硬件和固件加密一起提供更高的安全性。

启用数据保护后，只需在移动设备中设置密码，每个数据文件就会与特定的保护等级相关联。每个类都支持不同级别的可访问性，并根据需要访问数据的时间来保护数据。与每个类关联的加密和解密操作基于多个密钥机制，这些机制利用设备的 UID 和密码、类密钥、文件系统密钥和每个文件密钥。每个文件的密钥用于加密文件的内容。类密钥包裹在每个文件的密钥周围并存储在文件的元数据中。文件系统密钥用于加密元数据。UID 和密码保护类密钥。该操作对用户是不可见的。要启用数据保护，访问设备时必须使用密码。密码解锁设备。结合 UID，密码还创建了更能抵抗黑客攻击和暴力攻击的 iOS 加密密钥。启用数据保护是用户在其设备上使用密码的主要原因。

### 沙盒[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#sandbox)

appsandbox[是](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html)一种 iOS 访问控制技术。它在内核级别强制执行。其目的是限制应用程序遭到破坏时可能发生的系统和用户数据损坏。

自 iOS 首次发布以来，沙盒一直是一项核心安全功能。所有第三方应用程序都在同一用户 ( `mobile`) 下运行，只有少数系统应用程序和服务以`root`（或其他特定系统用户）身份运行。常规 iOS 应用程序被限制在一个*容器*中，该容器限制对应用程序自己的文件和数量非常有限的系统 API 的访问。对所有资源（例如文件、网络套接字、IPC 和共享内存）的访问都由沙箱控制。这些限制的工作方式如下 [#levin]：

- 应用程序进程通过类似 chroot 的进程被限制在它自己的目录（在 /var/mobile/Containers/Bundle/Application/ 或 /var/containers/Bundle/Application/ 下，取决于 iOS 版本）。
- 修改了`mmap`和`mmprotect`系统调用，以防止应用程序使可写内存页可执行并阻止进程执行动态生成的代码。结合代码签名和 FairPlay，这严格限制了在特定情况下可以运行的代码（例如，通过 App Store 分发的应用程序中的所有代码都经过 Apple 批准）。
- 进程彼此隔离，即使它们在操作系统级别由相同的 UID 拥有。
- 无法直接访问硬件驱动程序。相反，它们必须通过 Apple 的公共框架访问。

### 一般漏洞利用缓解措施[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#general-exploit-mitigations)

iOS 实施地址空间布局随机化 (ASLR) 和 eXecute Never (XN) 位来减轻代码执行攻击。

ASLR 在程序每次执行时，将程序的可执行文件、数据、堆和栈的内存位置随机化。因为共享库必须是静态的才能被多个进程访问，所以共享库的地址在每次操作系统启动时都是随机的，而不是每次调用程序时。这使得特定函数和库的内存地址难以预测，从而防止诸如 return-to-libc 攻击之类的涉及基本 libc 函数内存地址的攻击。

XN 机制允许 iOS 将进程的选定内存段标记为不可执行。在 iOS 上，用户模式进程的进程栈和堆被标记为不可执行。可写页面不能同时标记为可执行。这可以防止攻击者执行注入堆栈或堆中的机器代码。

## iOS 软件开发[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#software-development-on-ios)

与其他平台一样，Apple 提供了软件开发工具包 (SDK)，可帮助开发人员开发、安装、运行和测试原生 iOS 应用程序。Xcode 是用于 Apple 软件开发的集成开发环境 (IDE)。iOS 应用程序是用 Objective-C 或 Swift 开发的。

Objective-C 是一种面向对象的编程语言，它在 C 编程语言中添加了 Smalltalk 风格的消息传递。它在 macOS 上用于开发桌面应用程序，在 iOS 上用于开发移动应用程序。Swift 是 Objective-C 的继承者，并允许与 Objective-C 的互操作性。

Swift 于 2014 年随 Xcode 6 一起引入。

在未越狱的设备上，有两种方法可以从 App Store 安装应用程序：

1. 通过企业移动设备管理。这需要由 Apple 签署的公司范围的证书。
2. 通过旁加载，即通过使用开发人员证书签署应用程序并通过 Xcode（或 Cydia Impactor）将其安装在设备上。可以使用相同的证书安装有限数量的设备。

## iOS 上的应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#apps-on-ios)

iOS 应用程序在 IPA（iOS App Store Package）档案中分发。IPA 文件是一个 ZIP 压缩档案，其中包含执行应用程序所需的所有代码和资源。

IPA 文件具有内置的目录结构。下面的示例在较高级别显示了此结构：

- `/Payload/`文件夹包含所有应用程序数据。我们将更详细地返回此文件夹的内容。
- `/Payload/Application.app`包含应用程序数据本身（ARM 编译代码）和关联的静态资源。
- `/iTunesArtwork`是用作应用程序图标的 512x512 像素 PNG 图像。
- `/iTunesMetadata.plist`包含各种信息，包括开发者名称和 ID、捆绑包标识符、版权信息、流派、应用程序名称、发布日期、购买日期等。
- `/WatchKitSupport/WK`是一个扩展包的例子。这个特定的包包含扩展委托和控制器，用于管理接口和响应 Apple Watch 上的用户交互。

### IPA 有效载荷 - 仔细观察[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#ipa-payloads-a-closer-look)

让我们仔细看看 IPA 容器中的不同文件。Apple 使用相对扁平的结构，几乎没有多余的目录来节省磁盘空间并简化文件访问。顶级 bundle 目录包含应用程序的可执行文件和应用程序使用的所有资源（例如，应用程序图标、其他图像和本地化内容。

- **MyApp**：包含已编译（不可读）应用程序源代码的可执行文件。
- **应用程序**：应用程序图标。
- **Info.plist**：配置信息，例如包 ID、版本号和应用程序显示名称。
- **启动图像**：显示特定方向的初始应用程序界面的图像。系统使用提供的启动图像之一作为临时背景，直到应用程序完全加载。
- **MainWindow.nib**：启动应用程序时加载的默认界面对象。然后，其他接口对象要么从其他 nib 文件加载，要么由应用程序以编程方式创建。
- **Settings.bundle**：要在“设置”应用程序中显示的特定于应用程序的首选项。
- **自定义资源文件**：非本地化资源放在顶级目录中，本地化资源放在应用程序包的特定语言子目录中。资源包括 nib 文件、图像、声音文件、配置文件、字符串文件以及应用程序使用的任何其他自定义数据文件。

应用程序支持的每种语言都存在一个 language.lproj 文件夹。它包含一个故事板和字符串文件。

- 故事板是 iOS 应用程序用户界面的可视化表示。它显示屏幕以及这些屏幕之间的连接。
- 字符串文件格式由一个或多个键值对和可选注释组成。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06a/iOS_project_folder.png)

在越狱设备上，您可以使用不同的工具为已安装的 iOS 应用程序恢复 IPA，这些工具允许解密主应用程序二进制文件并重建 IPA 文件。同样，在越狱设备上，您可以使用[IPA Installer](https://github.com/autopear/ipainstaller)安装 IPA 文件。在移动安全评估期间，开发人员通常会直接为您提供 IPA。他们可以向您发送实际文件或提供对他们使用的开发特定分发平台的访问权限，例如[TestFlight](https://developer.apple.com/testflight/)或[Visual Studio App Center](https://appcenter.ms/)。

### 应用权限[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#app-permissions)

与 Android 应用程序（Android 6.0（API 级别 23）之前）相比，iOS 应用程序没有预先分配的权限。相反，当应用程序首次尝试使用敏感 API 时，会要求用户在Runtime(运行时)授予权限。已被授予权限的应用程序列在“设置”>“隐私”菜单中，允许用户修改特定于应用程序的设置。Apple 将此权限概念称为[隐私控制](https://support.apple.com/en-sg/HT203033)。

iOS 开发人员无法直接设置请求的权限，这些将在访问敏感 API 时间接请求。例如，当访问用户的联系人时，在要求用户授予或拒绝访问权限时，对 CNContactStore 的任何调用都会阻止该应用程序。从 iOS 10.0 开始，应用程序必须包括他们请求的权限类型和他们需要访问的数据的使用描述键（例如，NSContactsUsageDescription）。

以下 API[需要用户许可](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)：

- 联系人
- 麦克风
- 日历
- 相机
- 提醒事项
- 家庭用品
- 相片
- 健康
- 运动活动和健身
- 语音识别
- 位置服务
- 蓝牙共享
- 媒体库
- 社交媒体账户

## iOS 应用程序攻击面[¶](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#ios-application-attack-surface)

iOS 应用程序攻击面由应用程序的所有组件组成，包括发布应用程序和支持其功能所需的支持材料。如果 iOS 应用程序不满足以下条件，则它可能容易受到攻击：

- 通过 IPC 通信或 URL 方案验证所有输入，另请参阅：
- [测试自定义 URL 方案](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-custom-url-schemes-mstg-platform-3)
- 验证用户在输入字段中的所有输入。
- 验证加载到 WebView 中的内容，另请参阅：
- [测试 iOS WebView](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-ios-webviews-mstg-platform-5)
- [判断原生方法是否通过 WebView 暴露](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#determining-whether-native-methods-are-exposed-through-webviews-mstg-platform-7)
- 与后端服务器安全通信或容易受到服务器和移动应用程序之间的中间人 (MITM) 攻击，另请参阅：
- [测试网络通信](https://mas.owasp.org/MASTG/General/0x04f-Testing-Network-Communication/#testing-network-communication)
- [iOS网络通讯](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/)
- 安全地存储所有本地数据，或从存储中加载不受信任的数据，另请参阅：
- [iOS 上的数据存储](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/#data-storage-on-ios)
- 保护自己免受受损环境、重新打包或其他本地攻击，另请参阅：
- [iOS反逆向防御](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#ios-anti-reversing-defenses)
