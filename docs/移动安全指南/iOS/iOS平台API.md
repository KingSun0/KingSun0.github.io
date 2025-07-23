# iOS 平台 API[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#ios-platform-apis)

## 测试应用程序权限 (MSTG-PLATFORM-1)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-app-permissions-mstg-platform-1)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview)

与 Android 不同的是，每个应用程序都以自己的用户 ID 运行，iOS 使所有第三方应用程序都在非特权`mobile`用户下运行。每个应用程序都有一个唯一的主目录并被沙盒化，因此它们无法访问受保护的系统资源或系统或其他应用程序存储的文件。这些限制是通过沙盒策略（也称为*配置文件*）实现的，这些策略由[Trusted BSD (MAC) 强制访问控制框架](http://www.trustedbsd.org/mac.html)通过内核扩展强制执行。*iOS 将通用沙箱配置文件应用于所有称为容器*的第三方应用程序。可以访问受保护的资源或数据（有些也称为[应用程序功能](https://developer.apple.com/support/app-capabilities/)），但它受到称为*权利的特殊权限的严格控制*.

某些权限可以由应用程序的开发人员配置（例如数据保护或钥匙串共享），并会在安装后直接生效。但是，对于其他人，应用程序第一次尝试访问受保护资源时会明确询问用户，[例如](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7)：

- 蓝牙外设
- 日历数据
- 相机
- 联系人
- 健康分享
- 健康更新
- 家庭用品
- 地点
- 麦克风
- 运动
- 音乐和媒体库
- 相片
- 提醒事项
- 西里
- 语音识别
- 电视提供商

尽管 Apple 敦促保护用户的隐私并[非常清楚如何请求权限](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/)，但应用程序出于不明显的原因请求太多权限的情况仍然存在。

相机、照片、日历数据、动作、联系人或语音识别等权限应该非常容易验证，因为应用程序是否需要它们来完成其任务应该很明显。让我们考虑以下关于照片权限的示例，如果授予该权限，则应用程序可以访问“相机胶卷”（iOS 默认系统范围内用于存储照片的位置）中的所有用户照片：

- 典型的 QR 码扫描应用程序显然需要相机才能运行，但也可能会请求照片许可。如果明确需要存储空间，并且根据所拍摄照片的敏感性，这些应用程序可能会更好地选择使用应用程序沙盒存储空间以避免其他应用程序（具有照片权限）访问它们。有关敏感数据存储的更多信息，请参阅“ [iOS 上](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/)的数据存储”一章。
- 一些应用程序需要上传照片（例如个人资料照片）。最新版本的 iOS 引入了新的 API，例如[`UIImagePickerController`](https://developer.apple.com/documentation/uikit/uiimagepickercontroller)(iOS 11+) 及其现代[替代品](https://developer.apple.com/videos/play/wwdc2020/10652/) [`PHPickerViewController`](https://developer.apple.com/documentation/photokit/phpickerviewcontroller)(iOS 14+)。这些 API 在与您的应用程序不同的进程上运行，通过使用它们，应用程序可以只读访问用户选择的图像，而不是整个“相机胶卷”。这被认为是避免请求不必要权限的最佳做法。

蓝牙或位置等其他权限需要更深入的验证步骤。应用程序可能需要它们才能正常运行，但这些任务处理的数据可能未得到适当保护。有关更多信息和一些示例，请参阅下面“静态分析”部分和“动态分析”部分中的“[源代码检查”。](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#source-code-inspection)

当收集或简单地处理（例如缓存）敏感数据时，应用程序应提供适当的机制来让用户控制它，例如能够撤销访问或删除它。但是，敏感数据可能不仅会被存储或缓存，还会通过网络发送。在这两种情况下，都必须确保应用程序正确遵循适当的最佳实践，在这种情况下，这涉及实施适当的数据保护和传输安全。有关如何保护此类数据的更多信息，请参阅“网络 API”一章。

如您所见，使用应用程序功能和权限主要涉及处理个人数据，因此是保护用户隐私的问题。有关详细信息，请参阅 Apple 开发者文档中的文章[“保护用户隐私”](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy)和[“访问受保护的资源”](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc)。

#### 设备能力[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#device-capabilities)

App Store 使用设备功能来确保只列出兼容的设备，因此允许下载应用程序。它们在密钥`Info.plist`下的应用程序文件中指定。[`UIRequiredDeviceCapabilities`](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/plist/info/UIRequiredDeviceCapabilities)

```
<key>UIRequiredDeviceCapabilities</key>
<array>
    <string>armv7</string>
</array>
```

> 通常您会发现该`armv7`功能，这意味着该应用程序仅针对 armv7 指令集进行编译，或者如果它是 32/64 位通用应用程序。

例如，应用程序可能完全依赖 NFC 来工作（例如[“NFC 标签阅读器”](https://itunes.apple.com/us/app/nfc-taginfo-by-nxp/id1246143596)应用程序）。根据[存档的 iOS 设备兼容性参考](https://developer.apple.com/library/archive/documentation/DeviceInformation/Reference/iOSDeviceCompatibility/DeviceCompatibilityMatrix/DeviceCompatibilityMatrix.html)，NFC 仅在 iPhone 7（和 iOS 11）上可用。开发人员可能希望通过设置`nfc`设备功能来排除所有不兼容的设备。

关于测试，您可以将其视为`UIRequiredDeviceCapabilities`应用程序正在使用某些特定资源的指示。与与应用功能相关的权利不同，设备功能不授予对受保护资源的任何权利或访问权限。为此可能需要额外的配置步骤，这些步骤对于每个功能都是非常特定的。

例如，如果 BLE 是应用程序的核心功能，Apple 的[核心蓝牙编程指南](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothOverview/CoreBluetoothOverview.html#//apple_ref/doc/uid/TP40013257-CH2-SW1)解释了需要考虑的不同事项：

- `bluetooth-le`可以设置设备功能以*限制*不支持 BLE 的设备下载其应用程序。
- [如果需要BLE 后台处理](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)，则应添加`bluetooth-peripheral`或`bluetooth-central`（两者）等应用程序功能。`UIBackgroundModes`

然而，这还不足以让应用程序访问蓝牙外设，`NSBluetoothPeripheralUsageDescription`密钥必须包含在`Info.plist`文件中，这意味着用户必须主动授予权限。有关详细信息，请参阅下面的“Info.plist 文件中的用途字符串”。

#### 权利[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#entitlements)

根据[Apple 的 iOS 安全指南](https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf)：

> 权利是登录到应用程序并允许超出Runtime(运行时)因素（如 UNIX 用户 ID）的身份验证的键值对。由于权利是经过数字签名的，因此无法更改。系统应用程序和守护进程广泛使用权利来执行特定的特权操作，否则这些操作将需要进程以 root 身份运行。这大大降低了受感染的系统应用程序或守护程序进行权限升级的可能性。

许多权利可以使用 Xcode 目标编辑器的“摘要”选项卡进行设置。其他权利需要编辑目标的权利属性列表文件或从用于运行应用程序的 iOS 配置文件继承。

[权利来源](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-SOURCES)：

1. 嵌入在用于对应用程序进行代码签名的配置文件中的权利，包括：
2. 在 Xcode 项目的目标功能选项卡上定义的功能，和/或：
3. 在应用程序的应用程序 ID 上启用服务，这些服务在证书、ID 和配置文件网站的标识符部分配置。
4. 配置文件生成服务注入的其他权利。
5. 来自代码签名权利文件的权利。

[权利目的地](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-DESTINATIONS)：

1. 应用程序的签名。
2. 应用程序的嵌入式配置文件。

[Apple Developer Documentation](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-APPENTITLEMENTS)也解释了：

- 在代码签名期间，与应用程序启用的功能/服务相对应的权利从 Xcode 选择对应用程序进行签名的供应配置文件转移到应用程序的签名。
- 配置文件在构建 ( `embedded.mobileprovision`) 期间嵌入到应用程序包中。
- Xcode 的“构建设置”选项卡中“代码签名权利”部分的权利被转移到应用程序的签名中。

例如，如果您想设置“默认数据保护”功能，则需要转到 Xcode 中的**Capabilities**选项卡并启用**Data Protection**。这是 Xcode 直接将其作为具有默认值的权利写入`<appname>.entitlements`文件。在 IPA 中，我们可能会在as 中找到它：`com.apple.developer.default-data-protection``NSFileProtectionComplete``embedded.mobileprovision`

```
<key>Entitlements</key>
<dict>
    ...
    <key>com.apple.developer.default-data-protection</key>
    <string>NSFileProtectionComplete</string>
</dict>
```

对于 HealthKit 等其他功能，必须征求用户的许可，因此仅添加权利是不够的，必须将特殊键和字符串添加到`Info.plist`应用程序的文件中。

以下部分将更详细地介绍上述文件以及如何使用它们执行静态和动态分析。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis)

从 iOS 10 开始，这些是您需要检查权限的主要区域：

- Info.plist 文件中的目的字符串
- 代码签名授权文件
- 嵌入式配置文件
- 已编译的应用程序二进制文件中嵌入的权利
- 源代码检查

#### Info.plist 文件中的目的字符串[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#purpose-strings-in-the-infoplist-file)

[*目的字符串*](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc#3037322)或_使用说明字符串_是在请求访问受保护数据或资源的权限时在系统的权限请求警报中提供给用户的自定义文本。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/permission_request_alert.png)

如果在 iOS 10 上或之后链接，开发人员需要在其应用[`Info.plist`](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW5)文件中包含目的字符串。否则，如果应用程序在未提供相应目的字符串的情况下尝试访问受保护的数据或资源，[则访问将失败，甚至可能导致应用程序崩溃](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc)。

如果有原始源代码，您可以验证`Info.plist`文件中包含的权限：

- 使用 Xcode 打开项目。
- 在默认编辑器中查找并打开`Info.plist`文件，然后搜索以`"Privacy -"`.

您可以通过右键单击并选择“显示原始键/值”来切换视图以显示原始值（例如，这种方式`"Privacy - Location When In Use Usage Description"`将变成`NSLocationWhenInUseUsageDescription`）。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/purpose_strings_xcode.png)

如果只有 IPA：

- 解压 IPA。

- `Info.plist`位于`Payload/<appname>.app/Info.plist`。_

- 如果需要（例如`plutil -convert xml1 Info.plist`）转换它，如“iOS 基本安全测试”一章，“Info.plist 文件”一节中所述。

- 检查所有*用途的字符串 Info.plist keys*，通常以以下结尾`UsageDescription`：

  ```
  <plist version="1.0">
  <dict>
      <key>NSLocationWhenInUseUsageDescription</key>
      <string>Your location is used to provide turn-by-turn directions to your destination.</string>
  ```

*有关可用的不同用途字符串 Info.plist 键*的概述，请参阅[Apple App Programming Guide for iOS](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7)中的表 1-2 。单击提供的链接可查看[CocoaKeys 参考](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html)中每个键的完整描述。

遵循这些准则应该可以相对简单地评估文件中的每个条目`Info.plist`以检查权限是否有意义。

例如，假设以下行是从`Info.plist`纸牌游戏使用的文件中提取的：

```
<key>NSHealthClinicalHealthRecordsShareUsageDescription</key>
<string>Share your health data with us!</string>
<key>NSCameraUsageDescription</key>
<string>We want to access your camera</string>
```

应该怀疑常规纸牌游戏请求这种资源访问，因为它可能不需要[访问相机](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW24)或[用户的健康记录](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW76)。

除了简单地检查权限是否有意义之外，进一步的分析步骤可能来自分析目的字符串，例如它们是否与存储敏感数据相关。例如，`NSPhotoLibraryUsageDescription`可以被视为一种存储权限，允许访问应用程序沙箱之外的文件，并且其他应用程序也可以访问这些文件。在这种情况下，应该测试没有敏感数据存储在那里（在这种情况下是照片）。对于其他用途的字符串，如`NSLocationAlwaysUsageDescription`，还必须考虑应用程序是否安全地存储此数据。有关安全存储敏感数据的更多信息和最佳实践，请参阅“测试数据存储”一章。

#### 代码签名授权文件[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#code-signing-entitlements-file)

某些功能需要[代码签名授权文件](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-ENTITLEMENTSFILE)( `<appname>.entitlements`)。它由 Xcode 自动生成，但也可以由开发人员手动编辑和/或扩展。

以下是[开源应用程序 Telegram](https://github.com/peter-iakovlev/Telegram-iOS/blob/77ee5c4dabdd6eb5f1e2ff76219edf7e18b45c00/Telegram-iOS/Telegram-iOS-AppStoreLLC.entitlements#L23)的权利文件示例，包括[应用程序组权利](https://developer.apple.com/documentation/foundation/com_apple_security_application-groups)( `application-groups`)：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
...
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.ph.telegra.Telegraph</string>
    </array>
</dict>
...
</plist>
```

上述权利不需要用户的任何额外许可。但是，检查所有权利始终是一个好习惯，因为应用程序可能会在权限方面过度询问用户，从而泄露信息。

正如[Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html#//apple_ref/doc/uid/TP40011195-CH4-SW19)中所记录的，App Groups 授权需要通过 IPC 或共享文件容器在不同应用程序之间共享信息，这意味着数据可以在应用程序之间直接在设备上共享。如果应用程序扩展需要[与其包含的应用程序共享信息，](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html)则也需要此权利。

根据要共享的数据，使用其他方法共享它可能更合适，例如通过可能验证此数据的后端，避免被用户自己篡改。

#### 嵌入式配置文件[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#embedded-provisioning-profile-file)

当您没有原始源代码时，您应该分析 IPA 并在内部搜索通常位于根应用程序包文件夹 ( ) 中名称下的*嵌入式配置文件*。`Payload/<appname>.app/``embedded.mobileprovision`

该文件不是`.plist`，它是使用[加密消息语法](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax)编码的。在 macOS 上，您可以使用以下命令[检查嵌入式配置文件的权利：](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-PROFILESENTITLEMENTS)

```
security cms -D -i embedded.mobileprovision
```

然后搜索 Entitlements 密钥区域 ( `<key>Entitlements</key>`)。

#### 已编译的应用程序二进制文件中嵌入的权利[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#entitlements-embedded-in-the-compiled-app-binary)

如果您只有应用程序的 IPA 或只有越狱设备上安装的应用程序，您通常无法找到`.entitlements`文件。文件也可能是这种情况`embedded.mobileprovision`。不过，您应该能够自己从应用程序二进制文件中提取权利属性列表（您之前已按照“iOS 基本安全测试”一章的[“获取应用程序二进制文件”](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#acquiring-the-app-binary)一节中的说明获得）。

即使针对加密的二进制文件，以下步骤也应该有效。如果由于某种原因他们不这样做，您将不得不使用 Clutch（如果与您的 iOS 版本兼容）、frida-ios-dump 或类似工具来解密和提取应用程序。

##### 从应用程序二进制文件中提取权利 PLIST[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#extracting-the-entitlements-plist-from-the-app-binary)

如果您的计算机中有应用二进制文件，一种方法是使用 binwalk 提取 ( `-e`) 所有 XML 文件 ( `-y=xml`)：

```
$ binwalk -e -y=xml ./Telegram\ X

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1430180       0x15D2A4        XML document, version: "1.0"
1458814       0x16427E        XML document, version: "1.0"
```

或者您可以使用 radare2（*安静地*`-qc`运行一个命令并退出）来搜索包含“PropertyList”（）的应用程序二进制文件（）中的所有字符串：`izz``~PropertyList`

```
$ r2 -qc 'izz~PropertyList' ./Telegram\ X

0x0015d2a4 ascii <?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<!DOCTYPE plist PUBLIC
"-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">
...<key>com.apple.security.application-groups</key>\n\t\t<array>
\n\t\t\t<string>group.ph.telegra.Telegraph</string>...

0x0016427d ascii H<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC
"-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n
<dict>\n\t<key>cdhashes</key>...
```

在这两种情况下（binwalk 或 radare2）我们都能够提取相同的两个`plist`文件。如果我们检查第一个 (0x0015d2a4)，我们会发现我们能够[从 Telegram 中完全恢复原始权利文件](https://github.com/peter-iakovlev/Telegram-iOS/blob/77ee5c4dabdd6eb5f1e2ff76219edf7e18b45c00/Telegram-iOS/Telegram-iOS-AppStoreLLC.entitlements)。

> 注意：该`strings`命令在这里没有帮助，因为它无法找到此信息。最好`-a`直接在二进制文件上使用带有标志的 grep 或使用 radare2 ( `izz`)/rabin2 ( `-zz`)。

如果您在越狱设备上访问应用程序二进制文件（例如通过 SSH），您可以使用带有`-a, --text`标志的 grep（将所有文件视为 ASCII 文本）：

```
$ grep -a -A 5 'PropertyList' /var/containers/Bundle/Application/
    15E6A58F-1CA7-44A4-A9E0-6CA85B65FA35/Telegram X.app/Telegram\ X

<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>com.apple.security.application-groups</key>
        <array>
        ...
```

玩`-A num, --after-context=num`旗帜以显示更多或更少的线条。如果您的越狱 iOS 设备上也安装了上述工具，您也可以使用这些工具。

> 即使应用程序二进制文件仍处于加密状态（已针对多个 App Store 应用程序进行了测试），此方法也应该有效。

#### 源代码检查[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#source-code-inspection)

检查完`<appname>.entitlements`文件和`Info.plist`文件后，就该验证请求的权限和分配的功能是如何使用的了。为此，源代码审查就足够了。但是，如果您没有原始源代码，验证权限的使用可能会特别具有挑战性，因为您可能需要对应用程序进行逆向工程，请参阅“动态分析”以了解有关如何进行的更多详细信息。

在进行源代码审查时，请注意：

- 文件中的*目的字符串*是否`Info.plist`与编程实现相匹配。
- 注册能力的使用方式是否不会泄露机密信息。

用户可以随时通过“设置”授予或撤销授权，因此应用程序通常会在访问某个功能之前检查其授权状态。这可以通过使用可用于提供对受保护资源的访问的许多系统框架的专用 API 来完成。

您可以使用[Apple 开发者文档](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc#3037319)作为起点。例如：

- 蓝牙：该类的[`state`](https://developer.apple.com/documentation/corebluetooth/cbmanager/1648600-state?language=objc)属性[`CBCentralManager`](https://developer.apple.com/documentation/corebluetooth/cbcentralmanager?language=objc)用于检查使用蓝牙外围设备的系统授权状态。

- 位置：搜索 的方法`CLLocationManager`，例如[`locationServicesEnabled`](https://developer.apple.com/documentation/corelocation/cllocationmanager/1423648-locationservicesenabled?language=objc)。

  ```
  func checkForLocationServices() {
      if CLLocationManager.locationServicesEnabled() {
          // Location services are available, so query the user’s location.
      } else {
          // Update your app’s UI to show that the location is unavailable.
      }
  }
  ```

  有关完整列表，请参阅[“确定位置服务的可用性”](https://developer.apple.com/documentation/corelocation/adding_location_services_to_your_app)（Apple 开发人员文档）中的表 1。

通过应用程序搜索这些 API 的用法，并检查可能从中获取的敏感数据发生了什么。例如，它可能通过网络存储或传输，如果是这种情况，应额外验证适当的数据保护和传输安全性。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis)

在静态分析的帮助下，您应该已经有了包含的权限和正在使用的应用程序功能的列表。但是，如“源代码检查”中所述，当您没有原始源代码时，发现与这些权限和应用程序功能相关的敏感数据和 API 可能是一项具有挑战性的任务。动态分析可以帮助获取输入以迭代静态分析。

按照下面介绍的方法应该可以帮助您发现提到的敏感数据和 API：

1. 考虑静态分析中确定的权限/功能列表（例如`NSLocationWhenInUseUsageDescription`）。
2. 将它们映射到可用于相应系统框架（例如`Core Location`）的专用 API。为此，您可以使用[Apple Developer Documentation](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc#3037319)。
3. 跟踪这些 API 的类或特定方法（例如`CLLocationManager`），例如，使用[`frida-trace`](https://www.frida.re/docs/frida-trace/).
4. 在访问相关功能（例如“共享您的位置”）时，确定应用程序真正使用了哪些方法。
5. 获取这些方法的回溯并尝试构建调用图。

一旦确定了所有方法，您就可以使用这些知识对应用程序进行逆向工程，并尝试找出数据的处理方式。这样做时，您可能会发现流程中涉及的新方法，您可以将其再次提供给上面的步骤 3，并在静态和动态分析之间不断迭代。

在下面的示例中，我们使用 Telegram 从聊天中打开共享对话框，并使用 frida-trace 来识别正在调用的方法。

首先，我们启动 Telegram 并开始跟踪所有与字符串“authorizationStatus”匹配的方法（这是一种通用方法，因为除了`CLLocationManager`实现此方法之外还有更多类）：

```
frida-trace -U "Telegram" -m "*[* *authorizationStatus*]"
```

> `-U`连接到 USB 设备。`-m`包括跟踪的 Objective-C 方法。您可以使用[glob 模式](https://en.wikipedia.org/wiki/Glob_(programming))（例如，使用“*”通配符，`-m "*[* *authorizationStatus*]"`意味着“包含任何包含‘authorizationStatus’的类的任何 Objective-C 方法”）。键入`frida-trace -h`以获取更多信息。

现在我们打开共享对话框：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/telegram_share_something.png)

显示以下方法：

```
  1942 ms  +[PHPhotoLibrary authorizationStatus]
  1959 ms  +[TGMediaAssetsLibrary authorizationStatusSignal]
  1959 ms     | +[TGMediaAssetsModernLibrary authorizationStatusSignal]
```

如果我们点击**Location**，将跟踪另一种方法：

```
 11186 ms  +[CLLocationManager authorizationStatus]
 11186 ms     | +[CLLocationManager _authorizationStatus]
 11186 ms     |    | +[CLLocationManager _authorizationStatusForBundleIdentifier:0x0 bundle:0x0]
```

使用 frida-trace 的自动生成存根来获取更多信息，例如返回值和回溯。对下面的JavaScript文件做如下修改（路径是相对于当前目录）：

```
// __handlers__/__CLLocationManager_authorizationStatus_.js

  onEnter: function (log, args, state) {
    log("+[CLLocationManager authorizationStatus]");
    log("Called from:\n" +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join("\n\t") + "\n");
  },
  onLeave: function (log, retval, state) {
    console.log('RET :' + retval.toString());
  }
```

再次点击“位置”显示更多信息：

```
  3630 ms  -[CLLocationManager init]
  3630 ms     | -[CLLocationManager initWithEffectiveBundleIdentifier:0x0 bundle:0x0]
  3634 ms  -[CLLocationManager setDelegate:0x14c9ab000]
  3641 ms  +[CLLocationManager authorizationStatus]
RET: 0x4
  3641 ms  Called from:
0x1031aa158 TelegramUI!+[TGLocationUtils requestWhenInUserLocationAuthorizationWithLocationManager:]
    0x10337e2c0 TelegramUI!-[TGLocationPickerController initWithContext:intent:]
    0x101ee93ac TelegramUI!0x1013ac
```

我们看到它`+[CLLocationManager authorizationStatus]`返回了`0x4`( [CLAuthorizationStatus.authorizedWhenInUse](https://developer.apple.com/documentation/corelocation/clauthorizationstatus/authorizedwheninuse) ) 并且被调用了`+[TGLocationUtils requestWhenInUserLocationAuthorizationWithLocationManager:]`。正如我们之前预期的那样，您可能会在对应用程序进行逆向工程时使用此类信息作为入口点，并从那里获取输入（例如类或方法的名称）以继续提供动态分析。

接下来，通过打开“设置”并向下滚动直到找到您感兴趣的应用程序，可以在使用 iPhone/iPad 时通过*可视化*方式检查某些应用程序权限的状态。单击它时，这将打开“允许 APP_NAME 访问”屏幕。但是，可能尚未显示所有权限。您必须触发它们才能在该屏幕上列出。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/settings_allow_screen.png)

例如，在前面的示例中，直到我们第一次触发权限对话时，“位置”条目才被列出。一旦我们这样做了，无论我们是否允许访问，都会显示“位置”条目。

## 通过 IPC 测试敏感功能暴露 (MSTG-PLATFORM-4)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-for-sensitive-functionality-exposure-through-ipc-mstg-platform-4)

在移动应用程序的实现过程中，开发人员可能会应用传统的 IPC 技术（例如使用共享文件或网络套接字）。应该使用移动应用平台提供的IPC系统功能，因为它比传统技术成熟得多。在没有考虑安全性的情况下使用 IPC 机制可能会导致应用程序泄漏或暴露敏感数据。

与 Android 丰富的进程间通信 (IPC) 功能相比，iOS 为应用程序之间的通信提供了一些相当有限的选项。事实上，应用程序无法直接通信。在本节中，我们将介绍 iOS 提供的不同类型的间接通信以及如何测试它们。这是一个概述：

- 自定义 URL 方案
- 通用链接
- UIActivity 共享
- 应用扩展
- UI粘贴板

### 自定义 URL 方案[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#custom-url-schemes)

有关什么是自定义 URL 方案以及如何测试它们的更多信息，请参阅“[测试自定义 URL 方案”部分。](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-custom-url-schemes-mstg-platform-3)

### 通用链接[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#universal-links)

#### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_1)

通用链接在 iOS 中相当于 Android 应用程序链接（又名数字资产链接），用于深度链接。当点击一个通用链接（到应用程序的网站）时，用户将被无缝地重定向到相应的已安装应用程序，而无需通过 Safari。如果未安装该应用程序，该链接将在 Safari 中打开。

通用链接是标准网络链接 (HTTP/HTTPS)，不要与自定义 URL 方案混淆，后者最初也用于深度链接。

例如，Telegram 应用程序支持自定义 URL 方案和通用链接：

- `tg://resolve?domain=fridadotre`是自定义 URL 方案并使用该`tg://`方案。
- `https://telegram.me/fridadotre`是通用链接并使用该`https://`方案。

两者都会导致相同的操作，用户将被重定向到 Telegram 中指定的聊天室（在本例中为“fridadotre”）。然而，根据[Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/General/Conceptual/AppSearch/UniversalLinks.html) ，通用链接提供了一些在使用自定义 URL 方案时不适用的关键优势，并且是实施深度链接的推荐方式。具体来说，通用链接是：

- **唯一**性：与自定义 URL 方案不同，通用链接不能被其他应用声明，因为它们使用标准 HTTP 或 HTTPS 链接到应用的网站。引入它们是为了*防止*URL 方案劫持攻击（在原始应用程序之后安装的应用程序可能会声明相同的方案，并且系统可能会将所有新请求定位到最后安装的应用程序）。
- **安全**：当用户安装该应用程序时，iOS 会下载并检查上传到 Web 服务器的文件（Apple App Site Association 或 AASA），以确保该网站允许该应用程序代表其打开 URL。只有 URL 的合法所有者才能上传此文件，因此他们的网站与应用程序的关联是安全的。
- **灵活**：即使未安装应用程序，通用链接也可以使用。正如用户所期望的那样，点击网站链接将在 Safari 中打开内容。
- **简单**：一个 URL 适用于网站和应用程序。
- **Private**：其他应用可以与该应用通信而无需知道它是否已安装。

#### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_1)

在静态方法上测试通用链接包括执行以下操作：

- 检查关联域权利
- 检索 Apple App 站点关联文件
- 检查链接接收器方法
- 检查数据处理程序方法
- 检查应用程序是否正在调用其他应用程序的通用链接

##### 检查关联域授权[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-the-associated-domains-entitlement)

通用链接要求开发人员添加关联域授权，并在其中包含应用程序支持的域列表。

在 Xcode 中，转到**Capabilities**选项卡并搜索**Associated Domains**。您还可以检查`.entitlements`文件以查找`com.apple.developer.associated-domains`. 每个域都必须以 为前缀`applinks:`，例如`applinks:www.mywebsite.com`。

这是 Telegram 文件中的示例`.entitlements`：

```
    <key>com.apple.developer.associated-domains</key>
    <array>
        <string>applinks:telegram.me</string>
        <string>applinks:t.me</string>
    </array>
```

更多详细信息可以在[存档的 Apple 开发者文档](https://developer.apple.com/library/archive/documentation/General/Conceptual/AppSearch/UniversalLinks.html#//apple_ref/doc/uid/TP40016308-CH12-SW2)中找到。

如果您没有原始源代码，您仍然可以搜索它们，如“已编译的应用程序二进制文件中嵌入的权利”中所述。

##### 检索 APPLE APP 站点关联文件[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#retrieving-the-apple-app-site-association-file)

尝试`apple-app-site-association`使用您从上一步获得的关联域从服务器检索文件。此文件需要可通过 HTTPS 访问，无需任何重定向，位于`https://<domain>/apple-app-site-association`或`https://<domain>/.well-known/apple-app-site-association`.

您可以使用浏览器自行检索并导航至`https://<domain>/apple-app-site-association`，`https://<domain>/.well-known/apple-app-site-association`或使用位于 Apple 的 CDN `https://app-site-association.cdn-apple.com/a/v1/<domain>`。

或者，您可以使用[Apple App Site Association (AASA) Validator](https://branch.io/resources/aasa-validator/)。输入域后，它将显示文件，为您验证它并显示结果（例如，如果它没有通过 HTTPS 正确提供）。请参阅 apple.com 中的以下示例`https://www.apple.com/.well-known/apple-app-site-association`：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/apple-app-site-association-file_validation.png)

```
{
    "activitycontinuation": {
    "apps": [
        "W74U47NE8E.com.apple.store.Jolly"
    ]
    },
    "applinks": {
        "apps": [],
        "details": [
            {
            "appID": "W74U47NE8E.com.apple.store.Jolly",
            "paths": [
                "NOT /shop/buy-iphone/*",
                "NOT /us/shop/buy-iphone/*",
                "/xc/*",
                "/shop/buy-*",
                "/shop/product/*",
                "/shop/bag/shared_bag/*",
                "/shop/order/list",
                "/today",
                "/shop/watch/watch-accessories",
                "/shop/watch/watch-accessories/*",
                "/shop/watch/bands",
            ] } ] }
}
```

“applinks”中的“details”键包含可能包含一个或多个应用程序的数组的 JSON 表示形式。“appID”应与应用程序权利中的“application-identifier”键匹配。接下来，使用“路径”键，开发人员可以指定要在每个应用程序基础上处理的某些路径。一些应用程序，如 Telegram 使用独立的 * ( `"paths": ["*"]`) 以允许所有可能的路径。只有当某些应用程序不应处理网站的特定区域时**，**`"NOT "`开发人员才能通过在相应路径前添加 a（注意 T 后的空格）来限制访问，从而排除这些区域。还要记住，系统将按照数组中字典的顺序查找匹配项（第一个匹配项获胜）。

这种路径排除机制不应被视为一种安全功能，而是一种过滤器，开发人员可以使用它来指定哪些应用程序打开哪些链接。默认情况下，iOS 不会打开任何未经验证的链接。

请记住，通用链接验证发生在安装时。`applinks`iOS在其`com.apple.developer.associated-domains`授权中检索已声明域 ( ) 的 AASA 文件。如果验证不成功，iOS 将拒绝打开这些链接。验证失败的一些原因可能包括：

- AASA 文件不通过 HTTPS 提供。
- AASA 不可用。
- `appID`s 不匹配（这是恶意应用程序的情况*）*。iOS 将成功阻止任何可能的劫持攻击。

##### 检查链接接收器方法[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-the-link-receiver-method)

为了接收链接并适当地处理它们，app delegate 必须实现[`application:continueUserActivity:restorationHandler:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623072-application). 如果您有原始项目，请尝试搜索此方法。

请注意，如果应用程序使用[`openURL:options:completionHandler:`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc)通用链接打开应用程序网站，则该链接不会在应用程序中打开。由于呼叫源自应用程序，因此不会将其作为通用链接处理。

> 来自 Apple Docs：当 iOS 在用户点击通用链接后启动您的应用程序时，您会收到`NSUserActivity`一个`activityType`值为`NSUserActivityTypeBrowsingWeb`. 活动对象的`webpageURL`属性包含用户正在访问的 URL。网页 URL 属性始终包含 HTTP 或 HTTPS URL，您可以使用`NSURLComponents`API 来操作 URL 的组件。[...] 为了保护用户的隐私和安全，当您需要传输数据时，您不应该使用 HTTP；相反，请使用安全的传输协议，例如 HTTPS。

从上面的注释中我们可以强调：

- 提到的`NSUserActivity`对象来自`continueUserActivity`参数，如上面的方法所示。
- 的方案`webpageURL`必须是 HTTP 或 HTTPS（任何其他方案都应抛出异常）。/的[`scheme`实例属性](https://developer.apple.com/documentation/foundation/urlcomponents/1779624-scheme)可以用来验证这一点。`URLComponents``NSURLComponents`

如果您没有原始源代码，您可以使用 radare2 或 rabin2 来搜索链接接收器方法的二进制字符串：

```
$ rabin2 -zq Telegram\ X.app/Telegram\ X | grep restorationHan

0x1000deea9 53 52 application:continueUserActivity:restorationHandler:
```

##### 检查数据处理程序方法[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-the-data-handler-method)

您应该检查接收到的数据是如何验证的。Apple[对此明确警告](https://developer.apple.com/documentation/uikit/core_app/allowing_apps_and_websites_to_link_to_your_content/handling_universal_links)：

> 通用链接为您的应用程序提供了潜在的攻击媒介，因此请确保验证所有 URL 参数并丢弃任何格式错误的 URL。此外，将可用操作限制为不会危及用户数据的操作。例如，不允许通用链接直接删除内容或访问有关用户的敏感信息。在测试您的 URL 处理代码时，请确保您的测试用例包含格式不正确的 URL。

正如[Apple Developer Documentation](https://developer.apple.com/documentation/uikit/core_app/allowing_apps_and_websites_to_link_to_your_content/handling_universal_links)中所述，当 iOS 通过通用链接打开应用程序时，该应用程序会收到`NSUserActivity`一个`activityType`值为`NSUserActivityTypeBrowsingWeb`. 活动对象的`webpageURL`属性包含用户访问的 HTTP 或 HTTPS URL。以下 Swift 示例在打开 URL 之前验证了这一点：

```
func application(_ application: UIApplication, continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
    // ...
    if userActivity.activityType == NSUserActivityTypeBrowsingWeb, let url = userActivity.webpageURL {
        application.open(url, options: [:], completionHandler: nil)
    }

    return true
}
```

此外，请记住，如果 URL 包含参数，则在仔细清理和验证之前不应信任它们（即使来自受信任的域）。例如，它们可能已被攻击者欺骗或可能包含格式错误的数据。如果是这种情况，则必须丢弃整个 URL 以及通用链接请求。

`NSURLComponents`API 可用于解析和操作 URL 的组件。这也可以是方法`application:continueUserActivity:restorationHandler:`本身的一部分，或者可能发生在从它调用的单独方法上。以下[示例](https://developer.apple.com/documentation/uikit/core_app/allowing_apps_and_websites_to_link_to_your_content/handling_universal_links#3001935)演示了这一点：

```
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([Any]?) -> Void) -> Bool {
    guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
        let incomingURL = userActivity.webpageURL,
        let components = NSURLComponents(url: incomingURL, resolvingAgainstBaseURL: true),
        let path = components.path,
        let params = components.queryItems else {
        return false
    }

    if let albumName = params.first(where: { $0.name == "albumname" })?.value,
        let photoIndex = params.first(where: { $0.name == "index" })?.value {
        // Interact with album name and photo index

        return true

    } else {
        // Handle when album and/or album name or photo index missing

        return false
    }
}
```

最后，如上所述，请务必验证 URL 触发的操作不会暴露敏感信息或以任何方式危及用户数据。

##### 检查应用程序是否正在调用其他应用程序的通用链接[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-if-the-app-is-calling-other-apps-universal-links)

一个应用程序可能会通过通用链接调用其他应用程序，以便简单地触发某些操作或传输信息，在这种情况下，应该验证它没有泄露敏感信息。

如果您有原始源代码，您可以在其中搜索`openURL:options: completionHandler:`方法并检查正在处理的数据。

> 请注意，该`openURL:options:completionHandler:`方法不仅用于打开通用链接，还用于调用自定义 URL 方案。

这是 Telegram 应用程序中的示例：

```
}, openUniversalUrl: { url, completion in
    if #available(iOS 10.0, *) {
        var parsedUrl = URL(string: url)
        if let parsed = parsedUrl {
            if parsed.scheme == nil || parsed.scheme!.isEmpty {
                parsedUrl = URL(string: "https://\(url)")
            }
        }

        if let parsedUrl = parsedUrl {
            return UIApplication.shared.open(parsedUrl,
                        options: [UIApplicationOpenURLOptionUniversalLinksOnly: true as NSNumber],
                        completionHandler: { value in completion.completion(value)}
            )
```

请注意应用程序如何`scheme`在打开它之前将其调整为“https”，以及它如何使用仅当 URL 是有效的通用链接并且安装了`UIApplicationOpenURLOptionUniversalLinksOnly: true`能够[打开该 URL 的应用程序时才打开 URL](https://developer.apple.com/documentation/uikit/uiapplicationopenurloptionuniversallinksonly?language=objc)的选项。

如果您没有原始源代码，请在应用二进制文件的符号和字符串中搜索。例如，我们将搜索包含“openURL”的 Objective-C 方法：

```
$ rabin2 -zq Telegram\ X.app/Telegram\ X | grep openURL

0x1000dee3f 50 49 application:openURL:sourceApplication:annotation:
0x1000dee71 29 28 application:openURL:options:
0x1000df2c9 9 8 openURL:
0x1000df772 35 34 openURL:options:completionHandler:
```

正如预期的那样，`openURL:options:completionHandler:`是找到的（请记住它也可能存在，因为该应用程序打开自定义 URL 方案）。接下来，为确保没有泄露敏感信息，您必须执行动态分析并检查传输的数据。有关挂接和跟踪此方法的一些示例，请参阅“测试自定义 URL 方案”部分的“动态分析”中的“[识别和挂接 URL 处理程序方法”。](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#identifying-and-hooking-the-url-handler-method)

#### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_1)

如果应用程序正在实现通用链接，您应该从静态分析中获得以下输出：

- 关联域
- Apple App Site Association 文件
- 链接接收器方法
- 数据处理方法

您现在可以使用它来动态测试它们：

- 触发通用链接
- 识别有效的通用链接
- 跟踪链接接收器方法
- 检查链接的打开方式

##### 触发通用链接[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#triggering-universal-links)

不幸的是，与自定义 URL 方案不同，您无法通过直接在搜索栏中直接键入 Safari 中的通用链接来测试它们，因为 Apple 不允许这样做。但您可以随时使用其他应用程序（如 Notes 应用程序）测试它们：

- 打开笔记应用程序并创建一个新笔记。
- 编写包含域的链接。
- 在 Notes 应用程序中保留编辑模式。
- 长按链接打开它们（请记住，标准点击会触发默认选项）。

> 要从 Safari 执行此操作，您必须在网站上找到一个现有链接，一旦单击该链接，它将被识别为通用链接。这可能有点耗时。

或者，您也可以为此使用 Frida，有关更多详细信息，请参阅“[执行 URL 请求](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#performing-url-requests)”部分。

##### 识别有效的通用链接[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#identifying-valid-universal-links)

首先，我们将看到打开允许的通用链接和不允许的通用链接之间的区别。

从`apple-app-site-association`上面我们看到的apple.com我们选择了以下路径：

```
"paths": [
    "NOT /shop/buy-iphone/*",
    ...
    "/today",
```

其中一个应该提供“在应用程序中打开”选项，另一个不应该。

如果我们长按第一个 ( `http://www.apple.com/shop/buy-iphone/iphone-xr`)，它只会提供打开它的选项（在浏览器中）。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/forbidden_universal_link.png)

如果我们长按第二个 ( `http://www.apple.com/today`)，它会显示在 Safari 和“Apple Store”中打开它的选项：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/allowed_universal_link.png)

> 请注意，单击和长按之间存在差异。一旦我们长按一个链接并选择一个选项，例如“在 Safari 中打开”，这将成为所有未来点击的默认选项，直到我们再次长按并选择另一个选项。

如果我们通过Hook或跟踪在方法上重复该过程`application:continueUserActivity: restorationHandler:`，我们将在打开允许的通用链接后立即看到它是如何被调用的。为此，您可以使用例如`frida-trace`：

```
frida-trace -U "Apple Store" -m "*[* *restorationHandler*]"
```

##### 跟踪链接接收器方法[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#tracing-the-link-receiver-method)

本节说明如何跟踪链接接收器方法以及如何提取附加信息。对于这个例子，我们将使用 Telegram，因为它的文件没有限制`apple-app-site-association`：

```
{
    "applinks": {
        "apps": [],
        "details": [
            {
                "appID": "X834Q8SBVP.org.telegram.TelegramEnterprise",
                "paths": [
                    "*"
                ]
            },
            {
                "appID": "C67CF9S4VU.ph.telegra.Telegraph",
                "paths": [
                    "*"
                ]
            },
            {
                "appID": "X834Q8SBVP.org.telegram.Telegram-iOS",
                "paths": [
                    "*"
                ]
            }
        ]
    }
}
```

为了打开链接，我们还将使用具有以下模式的 Notes 应用程序和 frida-trace：

```
frida-trace -U Telegram -m "*[* *restorationHandler*]"
```

编写`https://t.me/addstickers/radare`（通过快速互联网搜索找到）并从 Notes 应用程序打开它。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/telegram_add_stickers_universal_link.png)

首先我们让 frida-trace 生成存根`__handlers__/`：

```
$ frida-trace -U Telegram -m "*[* *restorationHandler*]"
Instrumenting functions...
-[AppDelegate application:continueUserActivity:restorationHandler:]
```

您可以看到只找到并检测了一个函数。现在触发通用链接并观察痕迹。

```
298382 ms  -[AppDelegate application:0x10556b3c0 continueUserActivity:0x1c4237780
                restorationHandler:0x16f27a898]
```

您可以观察到实际上正在调用该函数。您现在可以将代码添加到存根中`__handlers__/`以获取更多详细信息：

```
// __handlers__/__AppDelegate_application_contin_8e36bbb1.js

  onEnter: function (log, args, state) {
    log("-[AppDelegate application: " + args[2] + " continueUserActivity: " + args[3] +
                     " restorationHandler: " + args[4] + "]");
    log("\tapplication: " + ObjC.Object(args[2]).toString());
    log("\tcontinueUserActivity: " + ObjC.Object(args[3]).toString());
    log("\t\twebpageURL: " + ObjC.Object(args[3]).webpageURL().toString());
    log("\t\tactivityType: " + ObjC.Object(args[3]).activityType().toString());
    log("\t\tuserInfo: " + ObjC.Object(args[3]).userInfo().toString());
    log("\trestorationHandler: " +ObjC.Object(args[4]).toString());
  },
```

新的输出是：

```
298382 ms  -[AppDelegate application:0x10556b3c0 continueUserActivity:0x1c4237780
                restorationHandler:0x16f27a898]
298382 ms  application:<Application: 0x10556b3c0>
298382 ms  continueUserActivity:<NSUserActivity: 0x1c4237780>
298382 ms       webpageURL:http://t.me/addstickers/radare
298382 ms       activityType:NSUserActivityTypeBrowsingWeb
298382 ms       userInfo:{
}
298382 ms  restorationHandler:<__NSStackBlock__: 0x16f27a898>
```

除了函数参数之外，我们还通过调用它们的一些方法来添加更多信息以获取更多详细信息，在本例中是关于`NSUserActivity`. 如果我们查看[Apple Developer Documentation](https://developer.apple.com/documentation/foundation/nsuseractivity?language=objc)，我们可以看到我们还可以从这个对象调用什么。

##### 检查链接的打开方式[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-how-the-links-are-opened)

如果您想了解更多有关哪个函数实际打开 URL 以及实际如何处理数据的信息，您应该继续调查。

扩展前面的命令以查明打开 URL 是否涉及任何其他功能。

```
frida-trace -U Telegram -m "*[* *restorationHandler*]" -i "*open*Url*"
```

> `-i`包括任何方法。您也可以在这里使用 glob 模式（例如，`-i "*open*Url*"`意思是“包含任何包含‘open’的函数，然后是‘Url’和其他东西”）

同样，我们首先让 frida-trace 生成存根`__handlers__/`：

```
$ frida-trace -U Telegram -m "*[* *restorationHandler*]" -i "*open*Url*"
Instrumenting functions...
-[AppDelegate application:continueUserActivity:restorationHandler:]
$S10TelegramUI0A19ApplicationBindingsC16openUniversalUrlyySS_AA0ac4OpenG10Completion...
$S10TelegramUI15openExternalUrl7account7context3url05forceD016presentationData18application...
$S10TelegramUI31AuthorizationSequenceControllerC7account7strings7openUrl5apiId0J4HashAC0A4Core19...
...
```

现在您可以看到一长串函数，但我们仍然不知道将调用哪些函数。再次触发通用链接，观察痕迹。

```
           /* TID 0x303 */
298382 ms  -[AppDelegate application:0x10556b3c0 continueUserActivity:0x1c4237780
                restorationHandler:0x16f27a898]
298619 ms     | $S10TelegramUI15openExternalUrl7account7context3url05forceD016presentationData
                18applicationContext20navigationController12dismissInputy0A4Core7AccountC_AA
                14OpenURLContextOSSSbAA012PresentationK0CAA0a11ApplicationM0C7Display0
                10NavigationO0CSgyyctF()
```

除了 Objective-C 方法之外，现在还有一种 Swift 函数也是您感兴趣的。

该 Swift 函数可能没有文档，但您可以使用`swift-demangle`via对其符号进行分解[`xcrun`](https://www.manpagez.com/man/1/xcrun/)：

> xcrun 可用于从命令行调用 Xcode 开发人员工具，而无需将它们放在路径中。在这种情况下，它会找到并运行 swift-demangle，这是一个用于 demangles Swift 符号的 Xcode 工具。

```
$ xcrun swift-demangle S10TelegramUI15openExternalUrl7account7context3url05forceD016presentationData
18applicationContext20navigationController12dismissInputy0A4Core7AccountC_AA14OpenURLContextOSSSbAA0
12PresentationK0CAA0a11ApplicationM0C7Display010NavigationO0CSgyyctF
```

导致：

```
---> TelegramUI.openExternalUrl(
    account: TelegramCore.Account, context: TelegramUI.OpenURLContext, url: Swift.String,
    forceExternal: Swift.Bool, presentationData: TelegramUI.PresentationData,
    applicationContext: TelegramUI.TelegramApplicationContext,
    navigationController: Display.NavigationController?, dismissInput: () -> ()) -> ()
```

这不仅为您提供了方法的类（或模块）、它的名称和参数，而且还显示了参数类型和返回类型，因此如果您需要更深入地研究，现在您知道从哪里开始了。

现在我们将使用此信息通过编辑存根文件正确打印参数：

```
// __handlers__/TelegramUI/_S10TelegramUI15openExternalUrl7_b1a3234e.js

  onEnter: function (log, args, state) {

    log("TelegramUI.openExternalUrl(account: TelegramCore.Account,
        context: TelegramUI.OpenURLContext, url: Swift.String, forceExternal: Swift.Bool,
        presentationData: TelegramUI.PresentationData,
        applicationContext: TelegramUI.TelegramApplicationContext,
        navigationController: Display.NavigationController?, dismissInput: () -> ()) -> ()");
    log("\taccount: " + ObjC.Object(args[0]).toString());
    log("\tcontext: " + ObjC.Object(args[1]).toString());
    log("\turl: " + ObjC.Object(args[2]).toString());
    log("\tpresentationData: " + args[3]);
    log("\tapplicationContext: " + ObjC.Object(args[4]).toString());
    log("\tnavigationController: " + ObjC.Object(args[5]).toString());
  },
```

这样，下次我们运行它时，我们会得到更详细的输出：

```
298382 ms  -[AppDelegate application:0x10556b3c0 continueUserActivity:0x1c4237780
                restorationHandler:0x16f27a898]
298382 ms  application:<Application: 0x10556b3c0>
298382 ms  continueUserActivity:<NSUserActivity: 0x1c4237780>
298382 ms       webpageURL:http://t.me/addstickers/radare
298382 ms       activityType:NSUserActivityTypeBrowsingWeb
298382 ms       userInfo:{
}
298382 ms  restorationHandler:<__NSStackBlock__: 0x16f27a898>

298619 ms     | TelegramUI.openExternalUrl(account: TelegramCore.Account,
context: TelegramUI.OpenURLContext, url: Swift.String, forceExternal: Swift.Bool,
presentationData: TelegramUI.PresentationData, applicationContext:
TelegramUI.TelegramApplicationContext, navigationController: Display.NavigationController?,
dismissInput: () -> ()) -> ()
298619 ms     |     account: TelegramCore.Account
298619 ms     |     context: nil
298619 ms     |     url: http://t.me/addstickers/radare
298619 ms     |     presentationData: 0x1c4e40fd1
298619 ms     |     applicationContext: nil
298619 ms     |     navigationController: TelegramUI.PresentationData
```

在那里您可以观察到以下内容：

- `application:continueUserActivity:restorationHandler:`它按预期从应用程序委托调用。
- `application:continueUserActivity:restorationHandler:`处理 URL 但不打开它，它要求`TelegramUI.openExternalUrl`这样做。
- 正在打开的 URL 是`https://t.me/addstickers/radare`。

您现在可以继续并尝试跟踪和验证数据是如何验证的。例如，如果您有两个通过通用链接*进行通信*的应用程序，您可以使用它通过在接收应用程序中挂接这些方法来查看发送应用程序是否正在泄漏敏感数据。这在您没有源代码时特别有用，因为您将能够检索您不会以其他方式看到的完整 URL，因为它可能是单击某个按钮或触发某些功能的结果。

在某些情况下，您可能会在`userInfo`对象`NSUserActivity`中找到数据。在前一种情况下，没有数据被传输，但其他情况可能是这种情况。要看到这一点，请务必Hook`userInfo`属性或直接从`continueUserActivity`Hook中的对象访问它（例如，通过添加像这样的一行`log("userInfo:" + ObjC.Object(args[3]).userInfo().toString());`）。

##### 关于通用链接和切换的最后说明[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#final-notes-about-universal-links-and-handoff)

通用链接和 Apple 的[Handoff 功能](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Handoff/HandoffFundamentals/HandoffFundamentals.html#//apple_ref/doc/uid/TP40014338)相关：

- 两者在接收数据时都依赖于相同的方法：

```
application:continueUserActivity:restorationHandler:
```

- 与通用链接一样，Handoff 的 Activity Continuation 必须在`com.apple.developer.associated-domains`授权和服务器`apple-app-site-association`文件中声明（在这两种情况下都通过关键字`"activitycontinuation":`）。有关示例，请参阅上面的“检索 Apple App 站点关联文件”。

[实际上，“Checking How the Links Are Opened”中的前面示例与“Handoff Programming Guide”](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Handoff/AdoptingHandoff/AdoptingHandoff.html#//apple_ref/doc/uid/TP40014338-CH2-SW10)中描述的“Web Browser-to-Native App Handoff”场景非常相似：

> 如果用户在原始设备上使用 Web 浏览器，并且接收设备是带有声明该属性的域部分的Native应用程序的 iOS 设备`webpageURL`，则 iOS 会启动Native应用程序并向其`NSUserActivity`发送`activityType`值为`NSUserActivityTypeBrowsingWeb`. 该`webpageURL`属性包含用户访问的 URL，而`userInfo`字典为空。

在上面的详细输出中，您可以看到`NSUserActivity`我们收到的对象完全符合上述几点：

```
298382 ms  -[AppDelegate application:0x10556b3c0 continueUserActivity:0x1c4237780
                restorationHandler:0x16f27a898]
298382 ms  application:<Application: 0x10556b3c0>
298382 ms  continueUserActivity:<NSUserActivity: 0x1c4237780>
298382 ms       webpageURL:http://t.me/addstickers/radare
298382 ms       activityType:NSUserActivityTypeBrowsingWeb
298382 ms       userInfo:{
}
298382 ms  restorationHandler:<__NSStackBlock__: 0x16f27a898>
```

在测试支持 Handoff 的应用程序时，这些知识应该对您有所帮助。

### UIActivity 共享[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#uiactivity-sharing)

#### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_2)

从 iOS 6 开始，第三方应用程序可以通过特定机制（[例如 AirDrop](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html#//apple_ref/doc/uid/TP40007072-CH6-SW3) ）共享数据（项目） 。从用户的角度来看，这个功能就是众所周知的全系统“共享活动表”，它会在点击“共享”按钮后出现。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/share_activity_sheet.png)

可用的内置共享机制（又名活动类型）包括：

- 空投
- 指定联系人
- 复制到粘贴板
- 邮件
- 信息
- 发到脸书
- 发推特

完整列表可以在[UIActivity.ActivityType](https://developer.apple.com/documentation/uikit/uiactivity/activitytype)中找到。如果认为不适合应用程序，开发人员可以排除其中一些共享机制。

#### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_2)

##### 发送项目[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#sending-items)

测试`UIActivity`Sharing 时要特别注意：

- 共享的数据（项目），
- 自定义活动，
- 排除的活动类型。

通过在. `UIActivity`_`UIActivityViewController`[`init(activityItems: applicationActivities:)`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622019-init)

正如我们之前提到的，可以通过控制器的[`excludedActivityTypes`属性](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622009-excludedactivitytypes)排除一些共享机制。强烈建议使用最新版本的 iOS 进行测试，因为可以排除的活动类型数量可能会增加。开发人员必须意识到这一点，并**明确排除**那些不适合应用程序数据的内容。有些活动类型可能甚至没有记录，例如“创建表盘”。

如果有源代码，你应该看看`UIActivityViewController`：

- 检查传递给`init(activityItems:applicationActivities:)`方法的活动。
- 检查它是否定义了自定义活动（也被传递给以前的方法）。
- 验证`excludedActivityTypes`，如果有的话。

如果您只有编译/安装的应用程序，请尝试搜索以前的方法和属性，例如：

```
$ rabin2 -zq Telegram\ X.app/Telegram\ X | grep -i activityItems
0x1000df034 45 44 initWithActivityItems:applicationActivities:
```

##### 接收物品[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#receiving-items)

收货时应检查：

- 如果应用程序通过查看导出/导入的 UTI（Xcode 项目的“信息”选项卡）来声明*自定义文档类型。*可以在[归档的 Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/UTIRef/Articles/System-DeclaredUniformTypeIdentifiers.html#//apple_ref/doc/uid/TP40009259)中找到所有系统声明的 UTI（统一类型标识符）的列表。
- 如果应用程序指定*了它可以*通过查看文档类型（Xcode 项目的“信息”选项卡）打开的任何文档类型。如果存在，它们由名称和一个或多个表示数据类型的 UTI 组成（例如，PNG 文件的“public.png”）。iOS 使用它来确定应用程序是否有资格打开给定文档（指定导出/导入的 UTI 是不够的）。
- 如果应用程序通过查看应用程序委托中的（或其弃用版本）的实现来正确*验证接收到的数据。*[`application:openURL:options:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623112-application?language=objc)[`UIApplicationDelegate application:openURL:sourceApplication:annotation:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623073-application?language=objc)

如果没有源代码，您仍然可以查看`Info.plist`文件并搜索：

- `UTExportedTypeDeclarations`/`UTImportedTypeDeclarations`如果应用程序声明了导出/导入的*自定义文档类型*。
- `CFBundleDocumentTypes`查看该应用程序是否指定*了它可以打开的任何文档类型*。

[在 Stackoverflow 上](https://stackoverflow.com/questions/21937978/what-are-utimportedtypedeclarations-and-utexportedtypedeclarations-used-for-on-i)可以找到有关这些键的使用的非常完整的解释。

让我们看一个真实世界的例子。我们将采用文件管理器应用程序并查看这些键。我们在这里使用了[objection](https://github.com/sensepost/objection)来读取`Info.plist`文件。

```
objection --gadget SomeFileManager run ios plist cat Info.plist
```

> 请注意，这与我们从手机检索 IPA 或通过 SSH 访问并导航到 IPA / 应用程序沙箱中的相应文件夹相同。然而，有反对意见，我们*离我们的目标只有一个命令*，这仍然可以被认为是静态分析。

我们注意到的第一件事是应用程序没有声明任何导入的自定义文档类型，但我们可以找到几个导出的：

```
UTExportedTypeDeclarations =     (
            {
        UTTypeConformsTo =             (
            "public.data"
        );
        UTTypeDescription = "SomeFileManager Files";
        UTTypeIdentifier = "com.some.filemanager.custom";
        UTTypeTagSpecification =             {
            "public.filename-extension" =                 (
                ipa,
                deb,
                zip,
                rar,
                tar,
                gz,
                ...
                key,
                pem,
                p12,
                cer
            );
        };
    }
);
```

该应用程序还声明了它打开的文档类型，因为我们可以找到密钥`CFBundleDocumentTypes`：

```
CFBundleDocumentTypes =     (
        {
        ...
        CFBundleTypeName = "SomeFileManager Files";
        LSItemContentTypes =             (
            "public.content",
            "public.data",
            "public.archive",
            "public.item",
            "public.database",
            "public.calendar-event",
            ...
        );
    }
);
```

我们可以看到，此文件管理器将尝试打开符合中列出的任何 UTI 的任何内容，`LSItemContentTypes`并且它已准备好打开具有中列出的扩展名的文件`UTTypeTagSpecification/"public.filename-extension"`。请注意这一点，因为如果您想在执行动态分析时处理不同类型的文件时搜索漏洞，这将很有用。

#### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_2)

##### 发送项目[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#sending-items_1)

通过执行动态检测，您可以轻松检查三项主要内容：

- The `activityItems`: 一组共享的项目。它们可能是不同的类型，例如，一个字符串和一张图片将通过消息传递应用程序共享。
- The ：表示应用自定义服务`applicationActivities`的对象数组。`UIActivity`
- ：`excludedActivityTypes`不支持的活动类型数组，例如`postToFacebook`。

为此，您可以做两件事：

- 钩住我们在静态分析中看到的方法（[`init(activityItems: applicationActivities:)`](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622019-init)）来获取`activityItems`和`applicationActivities`。
- [`excludedActivityTypes`通过Hook属性](https://developer.apple.com/documentation/uikit/uiactivityviewcontroller/1622009-excludedactivitytypes)找出排除的活动。

让我们看一个使用 Telegram 共享图片和文本文件的示例。首先准备好钩子，我们将使用 Frida REPL 并为此编写一个脚本：

```
Interceptor.attach(
ObjC.classes.
    UIActivityViewController['- initWithActivityItems:applicationActivities:'].implementation, {
  onEnter: function (args) {

    printHeader(args)

    this.initWithActivityItems = ObjC.Object(args[2]);
    this.applicationActivities = ObjC.Object(args[3]);

    console.log("initWithActivityItems: " + this.initWithActivityItems);
    console.log("applicationActivities: " + this.applicationActivities);

  },
  onLeave: function (retval) {
    printRet(retval);
  }
});

Interceptor.attach(
ObjC.classes.UIActivityViewController['- excludedActivityTypes'].implementation, {
  onEnter: function (args) {
    printHeader(args)
  },
  onLeave: function (retval) {
    printRet(retval);
  }
});

function printHeader(args) {
  console.log(Memory.readUtf8String(args[1]) + " @ " + args[1])
};

function printRet(retval) {
  console.log('RET @ ' + retval + ': ' );
  try {
    console.log(new ObjC.Object(retval).toString());
  } catch (e) {
    console.log(retval.toString());
  }
};
```

您可以将其存储为 JavaScript 文件，例如`inspect_send_activity_data.js`并像这样加载它：

```
frida -U Telegram -l inspect_send_activity_data.js
```

现在观察第一次分享图片时的输出：

```
[*] initWithActivityItems:applicationActivities: @ 0x18c130c07
initWithActivityItems: (
    "<UIImage: 0x1c4aa0b40> size {571, 264} orientation 0 scale 1.000000"
)
applicationActivities: nil
RET @ 0x13cb2b800:
<UIActivityViewController: 0x13cb2b800>

[*] excludedActivityTypes @ 0x18c0f8429
RET @ 0x0:
nil
```

然后是一个文本文件：

```
[*] initWithActivityItems:applicationActivities: @ 0x18c130c07
initWithActivityItems: (
    "<QLActivityItemProvider: 0x1c4a30140>",
    "<UIPrintInfo: 0x1c0699a50>"
)
applicationActivities: (
)
RET @ 0x13c4bdc00:
<_UIDICActivityViewController: 0x13c4bdc00>

[*] excludedActivityTypes @ 0x18c0f8429
RET @ 0x1c001b1d0:
(
    "com.apple.UIKit.activity.MarkupAsPDF"
)
```

你可以看到：

- 对于图片，活动项目是 a`UIImage`并且没有排除的活动。
- 对于文本文件，有两个不同的活动项目并被`com.apple.UIKit.activity. MarkupAsPDF`排除在外。

在前面的示例中，没有自定义`applicationActivities`活动，只有一个被排除的活动。然而，为了更好地说明您对其他应用程序的期望，我们使用另一个应用程序共享了一张图片，在这里您可以看到一堆应用程序活动和排除的活动（输出已编辑以隐藏原始应用程序的名称）：

```
[*] initWithActivityItems:applicationActivities: @ 0x18c130c07
initWithActivityItems: (
    "<SomeActivityItemProvider: 0x1c04bd580>"
)
applicationActivities: (
    "<SomeActionItemActivityAdapter: 0x141de83b0>",
    "<SomeActionItemActivityAdapter: 0x147971cf0>",
    "<SomeOpenInSafariActivity: 0x1479f0030>",
    "<SomeOpenInChromeActivity: 0x1c0c8a500>"
)
RET @ 0x142138a00:
<SomeActivityViewController: 0x142138a00>

[*] excludedActivityTypes @ 0x18c0f8429
RET @ 0x14797c3e0:
(
    "com.apple.UIKit.activity.Print",
    "com.apple.UIKit.activity.AssignToContact",
    "com.apple.UIKit.activity.SaveToCameraRoll",
    "com.apple.UIKit.activity.CopyToPasteboard",
)
```

##### 接收物品[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#receiving-items_1)

执行静态分析后，您将知道*应用程序可以打开的文档类型，*以及*它是否声明了任何自定义文档类型*和（部分）所涉及的方法。您现在可以使用它来测试接收部分：

- *从另一个应用程序与该应用程序共享*文件或通过 AirDrop 或电子邮件发送。选择文件，使其触发“打开方式...”对话框（也就是说，没有默认应用程序可以打开文件，例如 PDF）。
- Hook`application:openURL:options:`和在之前的静态分析中识别出的任何其他方法。
- 观察应用程序行为。
- 此外，您可以发送特定格式错误的文件和/或使用模糊测试技术。

为了用一个例子来说明这一点，我们从静态分析部分选择了相同的真实世界文件管理器应用程序并遵循以下步骤：

1. 通过 Airdrop 从另一台 Apple 设备（例如 MacBook）发送 PDF 文件。

2. 等待**AirDrop**弹出窗口出现，然后单击**接受**。

3. 由于没有可以打开文件的默认应用程序，它会切换到**打开方式...**弹出窗口。在那里，我们可以选择将打开文件的应用程序。下一个屏幕截图显示了这一点（我们使用 Frida 修改了显示名称以隐藏应用程序的真实名称）：

   ![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/airdrop_openwith.png)

4. 选择**SomeFileManager**后我们可以看到如下内容：

   ```
   (0x1c4077000)  -[AppDelegate application:openURL:options:]
   application: <UIApplication: 0x101c00950>
   openURL: file:///var/mobile/Library/Application%20Support
                       /Containers/com.some.filemanager/Documents/Inbox/OWASP_MASVS.pdf
   options: {
       UIApplicationOpenURLOptionsAnnotationKey =     {
           LSMoveDocumentOnOpen = 1;
       };
       UIApplicationOpenURLOptionsOpenInPlaceKey = 0;
       UIApplicationOpenURLOptionsSourceApplicationKey = "com.apple.sharingd";
       "_UIApplicationOpenURLOptionsSourceProcessHandleKey" = "<FBSProcessHandle: 0x1c3a63140;
                                                                   sharingd:605; valid: YES>";
   }
   0x18c7930d8 UIKit!__58-[UIApplication _applicationOpenURLAction:payload:origin:]_block_invoke
   ...
   0x1857cdc34 FrontBoardServices!-[FBSSerialQueue _performNextFromRunLoopSource]
   RET: 0x1
   ```

如您所见，发送应用程序是`com.apple.sharingd`URL 的方案是`file://`。请注意，一旦我们选择了应该打开文件的应用程序，系统已经将文件移动到相应的目的地，即应用程序的收件箱。然后，应用程序负责删除其收件箱中的文件。例如，此应用程序将文件移动到`/var/mobile/Documents/`收件箱或从收件箱中删除。

```
(0x1c002c760)  -[XXFileManager moveItemAtPath:toPath:error:]
moveItemAtPath: /var/mobile/Library/Application Support/Containers
                            /com.some.filemanager/Documents/Inbox/OWASP_MASVS.pdf
toPath: /var/mobile/Documents/OWASP_MASVS (1).pdf
error: 0x16f095bf8
0x100f24e90 SomeFileManager!-[AppDelegate __handleOpenURL:]
0x100f25198 SomeFileManager!-[AppDelegate application:openURL:options:]
0x18c7930d8 UIKit!__58-[UIApplication _applicationOpenURLAction:payload:origin:]_block_invoke
...
0x1857cd9f4 FrontBoardServices!__FBSSERIALQUEUE_IS_CALLING_OUT_TO_A_BLOCK__
RET: 0x1
```

如果查看堆栈跟踪，您可以看到如何`application:openURL:options:`调用`__handleOpenURL:`，调用了`moveItemAtPath:toPath:error:`。请注意，我们现在拥有此信息，但没有目标应用程序的源代码。我们必须做的第一件事很明确：钩子`application:openURL:options:`。关于剩下的，我们不得不稍微思考一下，想出我们可以开始跟踪并且与文件管理器相关的方法，例如，所有包含字符串“copy”、“move”、“remove”等的方法. 直到我们发现被调用的是`moveItemAtPath:toPath:error:`.

最后一件值得注意的事情是，这种处理传入文件的方式对于自定义 URL 方案是相同的。有关详细信息，请参阅“[测试自定义 URL 方案](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-custom-url-schemes-mstg-platform-3)”部分。

### 应用扩展[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#app-extensions)

#### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_3)

##### 什么是应用扩展[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#what-are-app-extensions)

与 iOS 8 一起，Apple 引入了 App Extensions。根据[Apple App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/index.html#//apple_ref/doc/uid/TP40014214-CH20-SW1)，应用程序扩展允许应用程序在与其他应用程序或系统交互时向用户提供自定义功能和内容。为了做到这一点，他们实施特定的、范围明确的任务，例如，定义用户单击“共享”按钮并选择某些应用程序或操作后会发生什么，为今日小部件提供内容或启用自定义键盘.

根据任务的不同，应用程序扩展将具有特定类型（且只有一种），即所谓的*扩展点*。一些值得注意的是：

- 自定义键盘：用自定义键盘替换 iOS 系统键盘，用于所有应用程序。
- 分享：发布到分享网站或与他人分享内容。
- 今天：也称为小部件，它们在通知中心的今天视图中提供内容或执行快速任务。

##### 应用扩展如何与其他应用交互[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#how-do-app-extensions-interact-with-other-apps)

这里有三个重要的元素：

- 应用程序扩展：是捆绑在包含应用程序中的扩展程序。主机应用程序与之交互。
- 主机应用：是触发另一个应用的应用扩展的（第三方）应用。
- 包含应用程序：是包含捆绑到其中的应用程序扩展的应用程序。

例如，用户在*主机应用程序*中选择文本，单击“共享”按钮并从列表中选择一个“应用程序”或操作。这会触发*包含应用程序*的*应用程序扩展*。应用程序扩展在宿主应用程序的上下文中显示其视图，并使用宿主应用程序提供的项目（在本例中为选定文本）来执行特定任务（例如，将其发布到社交网络上）。[请参阅Apple App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionOverview.html#//apple_ref/doc/uid/TP40014214-CH2-SW13)中的这张图片，它很好地总结了这一点：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/app_extensions_communication.png)

##### 安全注意事项[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#security-considerations)

从安全的角度来看，重要的是要注意：

- 应用程序扩展永远不会直接与其包含的应用程序通信（通常，它甚至不会在包含的应用程序扩展程序Runtime(运行时)运行）。
- 应用程序扩展和宿主应用程序通过进程间通信进行通信。
- 应用扩展的包含应用和宿主应用根本不通信。
- `openURL:completionHandler:`Today 小部件（没有其他应用程序扩展类型）可以通过调用类的方法请求系统打开其包含的应用程序`NSExtensionContext`。
- 任何应用程序扩展及其包含的应用程序都可以访问私有定义的共享容器中的共享数据。

此外：

- 应用扩展无法访问某些 API，例如 HealthKit。
- 他们无法使用 AirDrop 接收数据，但可以发送数据。
- 不允许长时间运行的后台任务，但可以启动上传或下载。
- 应用扩展无法访问 iOS 设备上的摄像头或麦克风（iMessage 应用扩展除外）。

#### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_3)

静态分析将处理：

- 验证应用程序是否包含应用程序扩展
- 确定支持的数据类型
- 检查与包含应用程序的数据共享
- 验证应用是否限制应用扩展的使用

##### 验证应用程序是否包含应用程序扩展[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#verifying-if-the-app-contains-app-extensions)

如果您有原始源代码，您可以使用 Xcode (cmd+shift+f) 搜索所有出现的位置`NSExtensionPointIdentifier`或查看“构建阶段/嵌入应用程序扩展”：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/xcode_embed_app_extensions.png)

在那里您可以找到所有嵌入式应用程序扩展的名称，后跟`.appex`，现在您可以导航到项目中的各个应用程序扩展。

如果没有原始源代码：

`NSExtensionPointIdentifier`在应用程序包（IPA 或已安装的应用程序）内的所有文件中进行 Grep ：

```
$ grep -nr NSExtensionPointIdentifier Payload/Telegram\ X.app/
Binary file Payload/Telegram X.app//PlugIns/SiriIntents.appex/Info.plist matches
Binary file Payload/Telegram X.app//PlugIns/Share.appex/Info.plist matches
Binary file Payload/Telegram X.app//PlugIns/NotificationContent.appex/Info.plist matches
Binary file Payload/Telegram X.app//PlugIns/Widget.appex/Info.plist matches
Binary file Payload/Telegram X.app//Watch/Watch.app/PlugIns/Watch Extension.appex/Info.plist matches
```

您还可以通过 SSH 访问，找到应用程序包并列出所有内部插件（默认情况下它们放置在那里）或反对：

```
ph.telegra.Telegraph on (iPhone: 11.1.2) [usb] # cd PlugIns
    /var/containers/Bundle/Application/15E6A58F-1CA7-44A4-A9E0-6CA85B65FA35/
    Telegram X.app/PlugIns

ph.telegra.Telegraph on (iPhone: 11.1.2) [usb] # ls
NSFileType      Perms  NSFileProtection    Read    Write     Name
------------  -------  ------------------  ------  -------   -------------------------
Directory         493  None                True    False     NotificationContent.appex
Directory         493  None                True    False     Widget.appex
Directory         493  None                True    False     Share.appex
Directory         493  None                True    False     SiriIntents.appex
```

我们现在可以看到与之前在 Xcode 中看到的相同的四个应用程序扩展。

##### 确定支持的数据类型[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#determining-the-supported-data-types)

这对于与主机应用程序共享数据很重要（例如通过共享或操作扩展）。当用户在宿主应用程序中选择某种数据类型并且它与此处定义的数据类型匹配时，宿主应用程序将提供扩展。值得注意的是这与`UIActivity`我们必须定义文档类型的数据共享之间的区别，也使用 UTI。应用程序不需要为此扩展。可以仅使用共享数据`UIActivity`。

检查应用程序扩展的`Info.plist`文件并搜索`NSExtensionActivationRule`. 该键指定所支持的数据以及例如支持的最大项目数。例如：

```
<key>NSExtensionAttributes</key>
    <dict>
        <key>NSExtensionActivationRule</key>
        <dict>
            <key>NSExtensionActivationSupportsImageWithMaxCount</key>
            <integer>10</integer>
            <key>NSExtensionActivationSupportsMovieWithMaxCount</key>
            <integer>1</integer>
            <key>NSExtensionActivationSupportsWebURLWithMaxCount</key>
            <integer>1</integer>
        </dict>
    </dict>
```

仅支持此处存在且不具有的数据`0`类型`MaxCount`。但是，通过使用所谓的谓词字符串来评估给定的 UTI，可以进行更复杂的过滤。有关这方面的更多详细信息，请参阅[Apple App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html#//apple_ref/doc/uid/TP40014214-CH21-SW8)。

##### 检查与包含应用程序的数据共享[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-data-sharing-with-the-containing-app)

请记住，应用程序扩展及其包含的应用程序无法直接访问彼此的容器。但是，可以启用数据共享。这是通过[“应用程序组”](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html#//apple_ref/doc/uid/TP40011195-CH4-SW19)和[`NSUserDefaults`](https://developer.apple.com/documentation/foundation/nsuserdefaults)API 完成的。[请参阅Apple App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html#//apple_ref/doc/uid/TP40014214-CH21-SW11)中的这张图：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/app_extensions_container_restrictions.png)

指南中还提到，如果应用扩展使用该类执行后台上传或下载，则应用必须设置共享容器`NSURLSession`，以便扩展及其包含的应用都可以访问传输的数据。

##### 验证应用程序是否限制应用程序扩展的使用[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#verifying-if-the-app-restricts-the-use-of-app-extensions)

可以使用以下方法拒绝特定类型的应用程序扩展：

- [`application:shouldAllowExtensionPointIdentifier:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623122-application?language=objc)

但是，目前仅适用于“自定义键盘”应用程序扩展（并且在测试通过键盘处理敏感数据的应用程序（例如银行应用程序）时应进行验证）。

#### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_3)

对于动态分析，我们可以在没有源代码的情况下执行以下操作以获取知识：

- 检查共享的项目
- 识别涉及的应用程序扩展

##### 检查共享的项目[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#inspecting-the-items-being-shared)

为此，我们应该Hook`NSExtensionContext - inputItems`数据源应用程序。

按照前面的 Telegram 示例，我们现在将使用文本文件（从聊天中收到）上的“共享”按钮在 Notes 应用程序中使用它创建一个笔记：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/telegram_share_extension.png)

如果我们运行跟踪，我们会看到以下输出：

```
(0x1c06bb420) NSExtensionContext - inputItems
0x18284355c Foundation!-[NSExtension _itemProviderForPayload:extensionContext:]
0x1828447a4 Foundation!-[NSExtension _loadItemForPayload:contextIdentifier:completionHandler:]
0x182973224 Foundation!__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S3__
0x182971968 Foundation!-[NSXPCConnection _decodeAndInvokeMessageWithEvent:flags:]
0x182748830 Foundation!message_handler
0x181ac27d0 libxpc.dylib!_xpc_connection_call_event_handler
0x181ac0168 libxpc.dylib!_xpc_connection_mach_event
...
RET: (
"<NSExtensionItem: 0x1c420a540> - userInfo:
{
    NSExtensionItemAttachmentsKey =     (
    "<NSItemProvider: 0x1c46b30e0> {types = (\n \"public.plain-text\",\n \"public.file-url\"\n)}"
    );
}"
)
```

在这里我们可以观察到：

- 这是通过 XPC 在后台发生的，具体来说，它是通过`NSXPCConnection`使用`libxpc.dylib`框架的一个实现的。
- UTI 包含在和`NSItemProvider`中，后者包含在Telegram的[“共享扩展”中](https://github.com/TelegramMessenger/Telegram-iOS/blob/master/Telegram/Share/Info.plist)。`public.plain-text``public.file-url``NSExtensionActivationRule`[`Info.plist`](https://github.com/TelegramMessenger/Telegram-iOS/blob/master/Telegram/Share/Info.plist)

##### 识别涉及的应用程序扩展[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#identifying-the-app-extensions-involved)

您还可以通过Hook找出哪个应用程序扩展正在处理您的请求和响应`NSExtension - _plugIn`：

我们再次运行相同的示例：

```
(0x1c0370200) NSExtension - _plugIn
RET: <PKPlugin: 0x1163637f0 ph.telegra.Telegraph.Share(5.3) 5B6DE177-F09B-47DA-90CD-34D73121C785
1(2) /private/var/containers/Bundle/Application/15E6A58F-1CA7-44A4-A9E0-6CA85B65FA35
/Telegram X.app/PlugIns/Share.appex>

(0x1c0372300)  -[NSExtension _plugIn]
RET: <PKPlugin: 0x10bff7910 com.apple.mobilenotes.SharingExtension(1.5) 73E4F137-5184-4459-A70A-83
F90A1414DC 1(2) /private/var/containers/Bundle/Application/5E267B56-F104-41D0-835B-F1DAB9AE076D
/MobileNotes.app/PlugIns/com.apple.mobilenotes.SharingExtension.appex>
```

如您所见，涉及两个应用程序扩展：

- `Share.appex`正在发送文本文件 (`public.plain-text`和`public.file-url`)。
- `com.apple.mobilenotes.SharingExtension.appex`它正在接收并将处理文本文件。

如果您想详细了解 XPC 的幕后情况，我们建议您查看来自“libxpc.dylib”的内部调用。例如，您可以使用[`frida-trace`](https://www.frida.re/docs/frida-trace/)并通过扩展自动生成的存根来深入挖掘您认为更有趣的方法。

### UI粘贴板[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#uipasteboard)

#### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_4)

在输入字段中键入数据时，剪贴板可用于复制数据。剪贴板可在系统范围内访问，因此由应用程序共享。这种共享可能会被恶意应用程序滥用，以获取已存储在剪贴板中的敏感数据。

使用应用程序时，您应该意识到其他应用程序可能会像[Facebook 应用程序](https://www.thedailybeast.com/facebook-is-spying-on-your-clipboard)一样持续读取剪贴板。在 iOS 9 之前，恶意应用程序可能会在后台监视粘贴板，同时定期检索`[UIPasteboard generalPasteboard].string`. 从 iOS 9 开始，粘贴板内容只能由前台的应用程序访问，这大大减少了从剪贴板嗅探密码的攻击面。不过，复制粘贴密码是您应该注意的安全风险，但应用程序也无法解决。

- 阻止粘贴到应用程序的输入字段，并不能阻止用户复制敏感信息。由于信息在用户注意到无法粘贴之前已经被复制，恶意应用程序已经嗅探了剪贴板。
- 如果在密码字段上禁用粘贴，用户甚至可能会选择他们可以记住的较弱的密码，并且他们无法再使用密码管理器，这与使应用程序更安全的初衷相矛盾。

允许在[`UIPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard)应用程序内共享数据，以及从一个应用程序到其他应用程序。粘贴板有两种：

- **全系统通用粘贴板**：用于与任何应用程序共享数据。默认情况下在设备重启和应用程序卸载时保持不变（自 iOS 10 起）。
- **自定义/命名粘贴板**：用于与另一个应用程序共享数据（与要共享的应用程序具有相同的团队 ID）或与应用程序本身（它们仅在创建它们的过程中可用）。默认情况下是非持久性的（自 iOS 10 起），也就是说，它们仅在拥有（创建）应用程序退出之前存在。

一些安全考虑：

- 用户不能授予或拒绝应用程序读取粘贴板的权限。
- 从 iOS 9 开始，应用程序[无法在后台访问粘贴板](https://forums.developer.apple.com/thread/13760)，这减轻了后台粘贴板监控。但是，如果*恶意*应用程序再次出现在前台并且数据保留在粘贴板中，它将能够在用户不知情或未经用户同意的情况下以编程方式检索数据。
- [Apple 警告持久命名粘贴板](https://developer.apple.com/documentation/uikit/uipasteboard?language=objc)并劝阻它们的使用。相反，应该使用共享容器。
- 从 iOS 10 开始，默认情况下启用了名为通用剪贴板的新 Handoff 功能。它允许一般的粘贴板内容在设备之间自动传输。如果开发人员选择这样做，则可以禁用此功能，也可以为复制的数据设置到期时间和日期。

#### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_4)

systemwide **general pasteboard**可以通过使用获得[`generalPasteboard`](https://developer.apple.com/documentation/uikit/uipasteboard/1622106-generalpasteboard?language=objc)，搜索源代码或编译后的二进制文件。处理敏感数据时，应避免使用系统范围的通用粘贴板。

可以使用[`pasteboardWithName:create:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622074-pasteboardwithname?language=objc)或创建**自定义粘贴板**[`pasteboardWithUniqueName`](https://developer.apple.com/documentation/uikit/uipasteboard/1622087-pasteboardwithuniquename?language=objc)。验证自定义粘贴板是否设置为持久性，因为自 iOS 10 以来已弃用。应改用共享容器。

此外，还可以检查以下内容：

- 检查粘贴板是否被删除[`removePasteboardWithName:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622072-removepasteboardwithname?language=objc)，这会使应用程序粘贴板无效，释放它使用的所有资源（对一般粘贴板没有影响）。
- 检查是否有排除的粘贴板，应该有一个`setItems:options:`带有`UIPasteboardOptionLocalOnly`选项的调用。
- 检查是否有过期的粘贴板，应该有一个`setItems:options:`带有`UIPasteboardOptionExpirationDate`选项的调用。
- 检查应用程序是否在进入后台或终止时滑动粘贴板项目。这是由一些试图限制敏感数据暴露的密码管理器应用程序完成的。

#### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_4)

##### 检测粘贴板使用情况[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#detect-pasteboard-usage)

钩住或追踪以下内容：

- `generalPasteboard`用于系统范围的通用粘贴板。
- `pasteboardWithName:create:`和`pasteboardWithUniqueName`自定义粘贴板。

##### 检测持久性粘贴板使用情况[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#detect-persistent-pasteboard-usage)

Hook或跟踪已弃用的[`setPersistent:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622096-setpersistent?language=objc)方法并验证它是否被调用。

##### 监视和检查粘贴板项目[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#monitoring-and-inspecting-pasteboard-items)

监视粘贴板时，可以动态检索几个详细信息：

- 通过Hook`pasteboardWithName:create:`并检查其输入参数或`pasteboardWithUniqueName`检查其返回值来获取粘贴板名称。
- 获取第一个可用的粘贴板项目：例如，对于字符串使用`string`方法。[或者对标准数据类型](https://developer.apple.com/documentation/uikit/uipasteboard?language=objc#1654275)使用任何其他方法。
- 获取带有 的项目数`numberOfItems`。
- [使用便捷方法](https://developer.apple.com/documentation/uikit/uipasteboard?language=objc#2107142)检查是否存在标准数据类型，例如`hasImages`, `hasStrings`，`hasURLs`（从 iOS 10 开始）。
- 使用 .检查其他数据类型（通常是 UTI）[`containsPasteboardTypes: inItemSet:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622100-containspasteboardtypes?language=objc)。您可以检查更具体的数据类型，例如作为 public.png 和 public.tiff ( [UTI](https://web.archive.org/web/20190616231857/https://developer.apple.com/documentation/mobilecoreservices/uttype) ) 的图片，或检查自定义数据，例如 com.mycompany.myapp.mytype。请记住，在这种情况下，只有那些*声明知道*该类型的应用程序才能理解写入粘贴板的数据。这与我们在“ [UIActivity Sharing](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#uiactivity-sharing) ”部分中看到的相同。[`itemSetWithPasteboardTypes:`](https://developer.apple.com/documentation/uikit/uipasteboard/1622071-itemsetwithpasteboardtypes?language=objc)使用并设置相应的 UTI检索它们。
- `setItems:options:`通过Hook并检查其 or 选项来`UIPasteboardOptionLocalOnly`检查排除的或过期的项目`UIPasteboardOptionExpirationDate`。

如果只查找字符串，您可能需要使用反对的命令`ios pasteboard monitor`：

> 连接到 iOS UIPasteboard 类并每 5 秒轮询一次 generalPasteboard 以获取数据。如果发现新数据，与之前的轮询不同，该数据将被转储到屏幕上。

您还可以构建自己的粘贴板监视器来监视特定信息，如上所示。

例如，这个脚本（灵感来自[objection's pasteboard monitor](https://github.com/sensepost/objection/blob/b39ee53b5ba2e9a271797d2f3931d79c46dccfdb/agent/src/ios/pasteboard.ts)背后的脚本）每 5 秒读取一次粘贴板项目，如果有新内容，它将打印出来：

```
const UIPasteboard = ObjC.classes.UIPasteboard;
    const Pasteboard = UIPasteboard.generalPasteboard();
    var items = "";
    var count = Pasteboard.changeCount().toString();

setInterval(function () {
      const currentCount = Pasteboard.changeCount().toString();
      const currentItems = Pasteboard.items().toString();

      if (currentCount === count) { return; }

      items = currentItems;
      count = currentCount;

      console.log('[* Pasteboard changed] count: ' + count +
      ' hasStrings: ' + Pasteboard.hasStrings().toString() +
      ' hasURLs: ' + Pasteboard.hasURLs().toString() +
      ' hasImages: ' + Pasteboard.hasImages().toString());
      console.log(items);

    }, 1000 * 5);
```

在输出中我们可以看到以下内容：

```
[* Pasteboard changed] count: 64 hasStrings: true hasURLs: false hasImages: false
(
    {
        "public.utf8-plain-text" = hola;
    }
)
[* Pasteboard changed] count: 65 hasStrings: true hasURLs: true hasImages: false
(
    {
        "public.url" = "https://codeshare.frida.re/";
        "public.utf8-plain-text" = "https://codeshare.frida.re/";
    }
)
[* Pasteboard changed] count: 66 hasStrings: false hasURLs: false hasImages: true
(
    {
        "com.apple.uikit.image" = "<UIImage: 0x1c42b23c0> size {571, 264} orientation 0 scale 1.000000";
        "public.jpeg" = "<UIImage: 0x1c44a1260> size {571, 264} orientation 0 scale 1.000000";
        "public.png" = "<UIImage: 0x1c04aaaa0> size {571, 264} orientation 0 scale 1.000000";
    }
)
```

你会看到首先复制了一个文本，包括字符串“hola”，然后复制了一个 URL，最后复制了一张图片。其中一些可通过不同的 UTI 获得。其他应用程序将考虑这些 UTI 是否允许粘贴此数据。

## 测试自定义 URL 方案 (MSTG-PLATFORM-3)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-custom-url-schemes-mstg-platform-3)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_5)

自定义 URL 方案[允许应用程序通过自定义协议进行通信](https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html#//apple_ref/doc/uid/TP40007072-CH6-SW1)。应用程序必须声明对方案的支持并处理使用这些方案的传入 URL。

[Apple 在Apple Developer Documentation](https://developer.apple.com/documentation/uikit/core_app/allowing_apps_and_websites_to_link_to_your_content/defining_a_custom_url_scheme_for_your_app)中警告不当使用自定义 URL 方案：

> URL 方案为您的应用程序提供了潜在的攻击媒介，因此请确保验证所有 URL 参数并丢弃任何格式错误的 URL。此外，将可用操作限制为不会危及用户数据的操作。例如，不允许其他应用程序直接删除内容或访问有关用户的敏感信息。在测试您的 URL 处理代码时，请确保您的测试用例包含格式不正确的 URL。

如果目的是实现深度链接，他们还建议改用通用链接：

> 虽然自定义 URL 方案是一种可接受的深度链接形式，但强烈建议将通用链接作为最佳做法。

支持自定义 URL 方案是通过以下方式完成的：

- 定义应用程序 URL 的格式，
- 注册方案，以便系统将适当的 URL 定向到应用程序，
- 处理应用接收到的 URL。

当应用程序在未正确验证 URL 及其参数的情况下处理对其 URL 方案的调用时，以及在触发重要操作之前未提示用户进行确认时，就会出现安全问题。

[一个例子是 2010 年发现的 Skype Mobile 应用程序中](http://www.dhanjani.com/blog/2010/11/insecure-handling-of-url-schemes-in-apples-ios.html)的以下错误：Skype 应用程序注册了`skype://`协议处理程序，这允许其他应用程序触发对其他 Skype 用户和电话号码的呼叫。不幸的是，Skype 在拨打电话之前没有征求用户的许可，因此任何应用程序都可以在用户不知情的情况下拨打任意号码。攻击者通过放置一个不可见的`<iframe src="skype://xxx?call"></iframe>`（`xxx`被付费号码代替的地方）来利用此漏洞，因此任何无意中访问恶意网站的 Skype 用户都会拨打付费号码。

作为开发人员，您应该在调用任何 URL 之前仔细验证它。您可以只允许某些可以通过已注册的协议处理程序打开的应用程序。提示用户确认 URL 调用的操作是另一个有用的控件。

所有 URL 都会在启动时或应用程序Runtime(运行时)或在后台传递给应用程序委托。要处理传入的 URL，委托应实现以下方法：

- 检索有关 URL 的信息并决定是否要打开它，
- 打开 URL 指定的资源。

更多信息可以在[存档的 iOS 应用程序编程指南](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html#//apple_ref/doc/uid/TP40007072-CH6-SW13)和[Apple 安全编码指南](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/ValidatingInput.html)中找到。

此外，应用程序可能还想向其他应用程序发送 URL 请求（也称为查询）。这是通过以下方式完成的：

- 注册应用程序要查询的应用程序查询方案，
- 可选地查询其他应用程序以了解它们是否可以打开某个 URL，
- 发送 URL 请求。

所有这些都代表了一个广泛的攻击面，我们将在静态和动态分析部分解决这个问题。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_5)

在静态分析中我们可以做几件事。在接下来的部分中，我们将看到以下内容：

- 测试自定义 URL 方案注册
- 测试应用查询方案注册
- 测试 URL 处理和验证
- 测试对其他应用程序的 URL 请求
- 测试已弃用的方法

#### 测试自定义 URL 方案注册[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-custom-url-schemes-registration)

测试自定义 URL 方案的第一步是查明应用程序是否注册了任何协议处理程序。

如果您有原始源代码并想查看已注册的协议处理程序，只需在 Xcode 中打开项目，转到“**信息**”选项卡并打开“ **URL 类型**”部分，如下面的屏幕截图所示：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/URL_scheme.png)

同样在 Xcode 中，您可以通过在应用程序文件中搜索`CFBundleURLTypes`密钥来找到它`Info.plist`（来自[iGoat-Swift](https://github.com/OWASP/iGoat-Swift)的示例）：

```
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>com.iGoat.myCompany</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>iGoat</string>
        </array>
    </dict>
</array>
```

在已编译的应用程序（或 IPA）中，已注册的协议处理程序`Info.plist`位于应用程序包根文件夹的文件中。打开它并搜索`CFBundleURLSchemes`密钥，如果存在，它应该包含一个字符串数组（来自[iGoat-Swift](https://github.com/OWASP/iGoat-Swift)的示例）：

```
grep -A 5 -nri urlsch Info.plist
Info.plist:45:    <key>CFBundleURLSchemes</key>
Info.plist-46-    <array>
Info.plist-47-        <string>iGoat</string>
Info.plist-48-    </array>
```

注册 URL 方案后，其他应用程序可以打开注册该方案的应用程序，并通过创建适当格式的 URL 并使用该[`UIApplication openURL:options:completionHandler:`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc)方法打开它们来传递参数。

[iOS App Programming Guide 中的](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html#//apple_ref/doc/uid/TP40007072-CH6-SW7)注释：

> 如果有多个第三方应用程序注册处理相同的 URL 方案，目前没有确定哪个应用程序将获得该方案的过程。

这可能会导致 URL 方案劫持攻击（请参阅 [#thiel2] 中的第 136 页）。

#### 测试应用程序查询方案注册[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-application-query-schemes-registration)

在调用该`openURL:options:completionHandler:`方法之前，应用程序可以调用[`canOpenURL:`](https://developer.apple.com/documentation/uikit/uiapplication/1622952-canopenurl?language=objc)以验证目标应用程序是否可用。然而，由于此方法被恶意应用程序用作枚举已安装应用程序的方式，[因此从 iOS 9.0 开始，传递给它的 URL 方案也必须](https://developer.apple.com/documentation/uikit/uiapplication/1622952-canopenurl?language=objc#discussion)通过将`LSApplicationQueriesSchemes`密钥添加到应用程序的`Info.plist`文件和最多 50 个 URL 方案的数组来声明。

```
<key>LSApplicationQueriesSchemes</key>
    <array>
        <string>url_scheme1</string>
        <string>url_scheme2</string>
    </array>
```

`canOpenURL`将始终返回`NO`未声明的方案，无论是否安装了适当的应用程序。但是，此限制仅适用于`canOpenURL`.

**该`openURL:options:completionHandler:`方法仍将打开任何 URL 方案，即使`LSApplicationQueriesSchemes`数组已声明**，并根据结果返回`YES`/ 。`NO`

例如，Telegram 在其[`Info.plist`](https://github.com/TelegramMessenger/Telegram-iOS/blob/master/Telegram/Telegram-iOS/Info.plist#L233)这些查询方案中声明：

```
    <key>LSApplicationQueriesSchemes</key>
    <array>
        <string>dbapi-3</string>
        <string>instagram</string>
        <string>googledrive</string>
        <string>comgooglemaps-x-callback</string>
        <string>foursquare</string>
        <string>here-location</string>
        <string>yandexmaps</string>
        <string>yandexnavi</string>
        <string>comgooglemaps</string>
        <string>youtube</string>
        <string>twitter</string>
        ...
```

#### 测试 URL 处理和验证[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-url-handling-and-validation)

为了确定 URL 路径是如何构建和验证的，如果您有原始源代码，您可以搜索以下方法：

- `application:didFinishLaunchingWithOptions:`方法或`application:will-FinishLaunchingWithOptions:`：验证如何做出决定以及如何检索有关 URL 的信息。
- [`application:openURL:options:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623112-application?language=objc)：验证资源是如何打开的，即数据是如何被解析的，验证[选项](https://developer.apple.com/documentation/uikit/uiapplication/openurloptionskey)，特别是如果调用应用程序（[`sourceApplication`](https://developer.apple.com/documentation/uikit/uiapplication/openurloptionskey/1623128-sourceapplication)）的访问应该被允许或拒绝。使用自定义 URL 方案时，应用程序可能还需要用户许可。

在 Telegram 中，您会[发现使用了四种不同的方法](https://github.com/peter-iakovlev/Telegram-iOS/blob/87e0a33ac438c1d702f2a0b75bf21f26866e346f/Telegram-iOS/AppDelegate.swift#L1250)：

```
func application(_ application: UIApplication, open url: URL, sourceApplication: String?) -> Bool {
    self.openUrl(url: url)
    return true
}

func application(_ application: UIApplication, open url: URL, sourceApplication: String?,
annotation: Any) -> Bool {
    self.openUrl(url: url)
    return true
}

func application(_ app: UIApplication, open url: URL,
options: [UIApplicationOpenURLOptionsKey : Any] = [:]) -> Bool {
    self.openUrl(url: url)
    return true
}

func application(_ application: UIApplication, handleOpen url: URL) -> Bool {
    self.openUrl(url: url)
    return true
}
```

我们可以在这里观察到一些事情：

- 该应用程序还实现了弃用的方法，例如[`application:handleOpenURL:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1622964-application?language=objc)和[`application:openURL:sourceApplication:annotation:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623073-application)。
- 源应用程序未在任何这些方法中进行验证。
- 他们都调用了一个私有`openUrl`方法。您可以[检查它](https://github.com/peter-iakovlev/Telegram-iOS/blob/87e0a33ac438c1d702f2a0b75bf21f26866e346f/Telegram-iOS/AppDelegate.swift#L1270)以了解有关如何处理 URL 请求的更多信息。

#### 测试对其他应用程序的 URL 请求[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-url-requests-to-other-apps)

的方法[`openURL:options:completionHandler:`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc)和[已弃用`openURL:`的方法`UIApplication`](https://developer.apple.com/documentation/uikit/uiapplication/1622961-openurl?language=objc)负责打开 URL（即向其他应用发送请求/进行查询），这些 URL 可能是当前应用的本地网址，也可能是必须由其他应用提供的网址。如果您有原始源代码，您可以直接搜索这些方法的用法。

此外，如果您有兴趣了解该应用程序是否正在查询特定服务或应用程序，并且该应用程序是否广为人知，您还可以在线搜索常见的 URL 方案并将它们包含在您的 greps 中。例如，[快速谷歌搜索显示](https://ios.gadgethacks.com/news/always-updated-list-ios-app-url-scheme-names-0184033/)：

```
Apple Music - music:// or musics:// or audio-player-event://
Calendar - calshow:// or x-apple-calevent://
Contacts - contacts://
Diagnostics - diagnostics:// or diags://
GarageBand - garageband://
iBooks - ibooks:// or itms-books:// or itms-bookss://
Mail - message:// or mailto://emailaddress
Messages - sms://phonenumber
Notes - mobilenotes://
...
```

我们在 Telegram 源代码中搜索这个方法，这次没有使用 Xcode，只是使用`egrep`：

```
$ egrep -nr "open.*options.*completionHandler" ./Telegram-iOS/

./AppDelegate.swift:552: return UIApplication.shared.open(parsedUrl,
    options: [UIApplicationOpenURLOptionUniversalLinksOnly: true as NSNumber],
    completionHandler: { value in
./AppDelegate.swift:556: return UIApplication.shared.open(parsedUrl,
    options: [UIApplicationOpenURLOptionUniversalLinksOnly: true as NSNumber],
    completionHandler: { value in
```

如果我们检查结果，我们会看到它`openURL:options:completionHandler:`实际上被用于通用链接，所以我们必须继续搜索。例如，我们可以搜索`openURL(`：

```
$ egrep -nr "openURL\(" ./Telegram-iOS/

./ApplicationContext.swift:763:  UIApplication.shared.openURL(parsedUrl)
./ApplicationContext.swift:792:  UIApplication.shared.openURL(URL(
                                        string: "https://telegram.org/deactivate?phone=\(phone)")!
                                 )
./AppDelegate.swift:423:         UIApplication.shared.openURL(url)
./AppDelegate.swift:538:         UIApplication.shared.openURL(parsedUrl)
...
```

如果我们检查这些行，我们将看到如何使用此方法打开“设置”或打开“App Store 页面”。

在搜索时`://`我们看到：

```
if documentUri.hasPrefix("file://"), let path = URL(string: documentUri)?.path {
if !url.hasPrefix("mt-encrypted-file://?") {
guard let dict = TGStringUtils.argumentDictionary(inUrlString: String(url[url.index(url.startIndex,
    offsetBy: "mt-encrypted-file://?".count)...])) else {
parsedUrl = URL(string: "https://\(url)")
if let url = URL(string: "itms-apps://itunes.apple.com/app/id\(appStoreId)") {
} else if let url = url as? String, url.lowercased().hasPrefix("tg://") {
[[WKExtension sharedExtension] openSystemURL:[NSURL URLWithString:[NSString
    stringWithFormat:@"tel://%@", userHandle.data]]];
```

结合两次搜索的结果并仔细检查源代码后，我们发现了以下代码：

```
openUrl: { url in
            var parsedUrl = URL(string: url)
            if let parsed = parsedUrl {
                if parsed.scheme == nil || parsed.scheme!.isEmpty {
                    parsedUrl = URL(string: "https://\(url)")
                }
                if parsed.scheme == "tg" {
                    return
                }
            }

            if let parsedUrl = parsedUrl {
                UIApplication.shared.openURL(parsedUrl)
```

在打开 URL 之前，将验证方案，必要时将添加“https”，并且不会打开任何带有“tg”方案的 URL。准备就绪后，它将使用已弃用的`openURL`方法。

如果只有编译后的应用程序 (IPA)，您仍然可以尝试确定哪些 URL 方案被用于查询其他应用程序：

- 检查是否`LSApplicationQueriesSchemes`已声明或搜索常见的 URL 方案。
- 还可以使用字符串`://`或构建正则表达式来匹配 URL，因为应用程序可能不会声明某些方案。

您可以通过首先验证应用程序二进制文件是否包含这些字符串来做到这一点，例如使用 unix`strings`命令：

```
strings <yourapp> | grep "someURLscheme://"
```

甚至更好的是，使用 radare2 的`iz/izz`命令或 rafind2，两者都会找到 unix`strings`命令找不到的字符串。来自 iGoat-Swift 的示例：

```
$ r2 -qc izz~iGoat:// iGoat-Swift
37436 0x001ee610 0x001ee610  23  24 (4.__TEXT.__cstring) ascii iGoat://?contactNumber=
```

#### 测试已弃用的方法[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-for-deprecated-methods)

搜索已弃用的方法，例如：

- [`application:handleOpenURL:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1622964-application?language=objc)
- [`openURL:`](https://developer.apple.com/documentation/uikit/uiapplication/1622961-openurl?language=objc)
- [`application:openURL:sourceApplication:annotation:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623073-application)

例如，我们在这里找到这三个：

```
$ rabin2 -zzq Telegram\ X.app/Telegram\ X | grep -i "openurl"

0x1000d9e90 31 30 UIApplicationOpenURLOptionsKey
0x1000dee3f 50 49 application:openURL:sourceApplication:annotation:
0x1000dee71 29 28 application:openURL:options:
0x1000dee8e 27 26 application:handleOpenURL:
0x1000df2c9 9 8 openURL:
0x1000df766 12 11 canOpenURL:
0x1000df772 35 34 openURL:options:completionHandler:
...
```

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_5)

确定应用已注册的自定义 URL 方案后，您可以使用多种方法对其进行测试：

- 执行 URL 请求
- 识别和Hook URL 处理程序方法
- 测试 URL 方案源验证
- 模糊 URL 方案

#### 执行 URL 请求[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#performing-url-requests)

##### 使用 SAFARI[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#using-safari)

要快速测试一个 URL 方案，您可以在 Safari 上打开 URL 并观察应用程序的行为方式。例如，如果您`tel://123456789`在 Safari 的地址栏中写入，将出现一个弹出窗口，其中包含*电话号码*以及“取消”和“呼叫”选项。如果您按“呼叫”，它将打开“电话”应用程序并直接拨打电话。

您可能还已经知道触发自定义 URL 方案的页面，您可以正常导航到这些页面，Safari 会在找到自定义 URL 方案时自动询问。

##### 使用笔记应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#using-the-notes-app)

如“触发通用链接”中所述，您可以使用 Notes 应用程序并长按您编写的链接以测试自定义 URL 方案。请记住退出编辑模式以便能够打开它们。请注意，只有在安装了该应用程序后，您才能单击或长按包括自定义 URL 方案的链接，否则它们不会突出显示为*可单击链接*。

##### 使用Frida[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#using-frida)

如果你只是想打开 URL scheme，你可以使用 Frida 来完成：

```
$ frida -U iGoat-Swift

[iPhone::iGoat-Swift]-> function openURL(url) {
                            var UIApplication = ObjC.classes.UIApplication.sharedApplication();
                            var toOpen = ObjC.classes.NSURL.URLWithString_(url);
                            return UIApplication.openURL_(toOpen);
                        }
[iPhone::iGoat-Swift]-> openURL("tel://234234234")
true
```

在[Frida CodeShare](https://codeshare.frida.re/@dki/ios-url-scheme-fuzzing/)的这个示例中，作者使用非公共 API`LSApplication Workspace.openSensitiveURL:withOptions:`打开 URL（来自 SpringBoard 应用程序）：

```
function openURL(url) {
    var w = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
    var toOpen = ObjC.classes.NSURL.URLWithString_(url);
    return w.openSensitiveURL_withOptions_(toOpen, null);
}
```

> 请注意，App Store 不允许使用非公共 API，这就是为什么我们甚至不测试这些 API，但允许我们使用它们进行动态分析。

#### 识别和Hook URL 处理程序方法[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#identifying-and-hooking-the-url-handler-method)

如果您无法查看原始源代码，您将不得不自己找出应用程序使用哪种方法来处理它收到的 URL 方案请求。您无法知道它是 Objective-C 方法还是 Swift 方法，或者即使应用程序使用的是已弃用的方法。

##### 自己制作链接并让 SAFARI 打开它[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#crafting-the-link-yourself-and-letting-safari-open-it)

为此，我们将使用 Frida CodeShare 的[ObjC 方法观察器](https://codeshare.frida.re/@mrmacete/objc-method-observer/)，这是一个非常方便的脚本，让您只需提供一个简单的模式即可快速观察任何方法或类的集合。

在这种情况下，我们对所有包含“openURL”的方法感兴趣，因此我们的模式将是`*[* *openURL*]`：

- 第一个星号将匹配所有实例`-`和类`+`方法。
- 第二个匹配所有 Objective-C 类。
- 第三个和第四个允许匹配任何包含字符串的方法`openURL`。

```
$ frida -U iGoat-Swift --codeshare mrmacete/objc-method-observer

[iPhone::iGoat-Swift]-> observeSomething("*[* *openURL*]");
Observing  -[_UIDICActivityItemProvider activityViewController:openURLAnnotationForActivityType:]
Observing  -[CNQuickActionsManager _openURL:]
Observing  -[SUClientController openURL:]
Observing  -[SUClientController openURL:inClientWithIdentifier:]
Observing  -[FBSSystemService openURL:application:options:clientPort:withResult:]
Observing  -[iGoat_Swift.AppDelegate application:openURL:options:]
Observing  -[PrefsUILinkLabel openURL:]
Observing  -[UIApplication openURL:]
Observing  -[UIApplication _openURL:]
Observing  -[UIApplication openURL:options:completionHandler:]
Observing  -[UIApplication openURL:withCompletionHandler:]
Observing  -[UIApplication _openURL:originatingView:completionHandler:]
Observing  -[SUApplication application:openURL:sourceApplication:annotation:]
...
```

该列表很长，包括我们已经提到的方法。如果我们现在触发一个 URL 方案，例如来自 Safari 的“igoat://”并接受在应用程序中打开它，我们将看到以下内容：

```
[iPhone::iGoat-Swift]-> (0x1c4038280)  -[iGoat_Swift.AppDelegate application:openURL:options:]
application: <UIApplication: 0x101d0fad0>
openURL: igoat://
options: {
    UIApplicationOpenURLOptionsOpenInPlaceKey = 0;
    UIApplicationOpenURLOptionsSourceApplicationKey = "com.apple.mobilesafari";
}
0x18b5030d8 UIKit!__58-[UIApplication _applicationOpenURLAction:payload:origin:]_block_invoke
0x18b502a94 UIKit!-[UIApplication _applicationOpenURLAction:payload:origin:]
...
0x1817e1048 libdispatch.dylib!_dispatch_client_callout
0x1817e86c8 libdispatch.dylib!_dispatch_block_invoke_direct$VARIANT$mp
0x18453d9f4 FrontBoardServices!__FBSSERIALQUEUE_IS_CALLING_OUT_TO_A_BLOCK__
0x18453d698 FrontBoardServices!-[FBSSerialQueue _performNext]
RET: 0x1
```

现在我们知道：

- 该方法`-[iGoat_Swift.AppDelegate application:openURL:options:]`被调用。正如我们之前所见，这是推荐的方式，并没有被弃用。
- 它接收我们的 URL 作为参数：`igoat://`。
- 我们还可以验证源应用程序：`com.apple.mobilesafari`.
- 正如预期的那样，我们也可以知道它是从哪里调用的`-[UIApplication _applicationOpenURLAction:payload:origin:]`。
- 该方法返回`0x1`这意味着`YES`（[委托成功处理了请求](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623112-application?language=objc#return-value)）。

调用成功，我们现在看到[iGoat](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat)应用程序已打开：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/iGoat_opened_via_url_scheme.jpg)

请注意，如果我们查看屏幕截图的左上角，我们还可以看到调用者（源应用程序）是 Safari。

##### 从应用程序本身动态打开链接[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamically-opening-the-link-from-the-app-itself)

查看在途中调用了哪些其他方法也很有趣。为了稍微改变结果，我们将从[iGoat](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat)应用程序本身调用相同的 URL 方案。我们将再次使用 ObjC 方法观察器和 Frida REPL：

```
$ frida -U iGoat-Swift --codeshare mrmacete/objc-method-observer

[iPhone::iGoat-Swift]-> function openURL(url) {
                            var UIApplication = ObjC.classes.UIApplication.sharedApplication();
                            var toOpen = ObjC.classes.NSURL.URLWithString_(url);
                            return UIApplication.openURL_(toOpen);
                        }

[iPhone::iGoat-Swift]-> observeSomething("*[* *openURL*]");
[iPhone::iGoat-Swift]-> openURL("iGoat://?contactNumber=123456789&message=hola")

(0x1c409e460)  -[__NSXPCInterfaceProxy__LSDOpenProtocol openURL:options:completionHandler:]
openURL: iGoat://?contactNumber=123456789&message=hola
options: nil
completionHandler: <__NSStackBlock__: 0x16fc89c38>
0x183befbec MobileCoreServices!-[LSApplicationWorkspace openURL:withOptions:error:]
0x10ba6400c
...
RET: nil

...

(0x101d0fad0)  -[UIApplication openURL:]
openURL: iGoat://?contactNumber=123456789&message=hola
0x10a610044
...
RET: 0x1

true
(0x1c4038280)  -[iGoat_Swift.AppDelegate application:openURL:options:]
application: <UIApplication: 0x101d0fad0>
openURL: iGoat://?contactNumber=123456789&message=hola
options: {
    UIApplicationOpenURLOptionsOpenInPlaceKey = 0;
    UIApplicationOpenURLOptionsSourceApplicationKey = "OWASP.iGoat-Swift";
}
0x18b5030d8 UIKit!__58-[UIApplication _applicationOpenURLAction:payload:origin:]_block_invoke
0x18b502a94 UIKit!-[UIApplication _applicationOpenURLAction:payload:origin:]
...
RET: 0x1
```

输出被截断以提高可读性。这次你看到它`UIApplicationOpenURLOptionsSourceApplicationKey`变成了`OWASP.iGoat-Swift`，这是有道理的。此外，调用了一长串类似`openURL`的方法。考虑到这些信息对于某些场景可能非常有用，因为它将帮助您决定下一步将是什么，例如，接下来您将Hook或篡改哪种方法。

##### 通过导航到页面并让 SAFARI 打开它来打开链接[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#opening-a-link-by-navigating-to-a-page-and-letting-safari-open-it)

您现在可以在单击页面上包含的链接时测试相同的情况。Safari 将识别和处理 URL 方案并选择要执行的操作。打开此链接“ https://telegram.me/fridadotre ”将触发此行为。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/open_in_telegram_via_urlscheme.png)

首先我们让 frida-trace 为我们生成存根：

```
$ frida-trace -U Telegram -m "*[* *restorationHandler*]" -i "*open*Url*"
    -m "*[* *application*URL*]" -m "*[* openURL]"

...
7310 ms  -[UIApplication _applicationOpenURLAction: 0x1c44ff900 payload: 0x10c5ee4c0 origin: 0x0]
7311 ms     | -[AppDelegate application: 0x105a59980 openURL: 0x1c46ebb80 options: 0x1c0e222c0]
7312 ms     | $S10TelegramUI15openExternalUrl7account7context3url05forceD016presentationData
            18applicationContext20navigationController12dismissInputy0A4Core7AccountC_AA14Open
            URLContextOSSSbAA012PresentationK0CAA0a11ApplicationM0C7Display010NavigationO0CSgyyctF()
```

现在我们可以简单地手动修改我们感兴趣的存根：

- Objective-C 方法`application:openURL:options:`：

  ```
  // __handlers__/__AppDelegate_application_openUR_3679fadc.js
  
  onEnter: function (log, args, state) {
      log("-[AppDelegate application: " + args[2] +
                  " openURL: " + args[3] + " options: " + args[4] + "]");
      log("\tapplication :" + ObjC.Object(args[2]).toString());
      log("\topenURL :" + ObjC.Object(args[3]).toString());
      log("\toptions :" + ObjC.Object(args[4]).toString());
  },
  ```

- Swift方法`$S10TelegramUI15openExternalUrl...`：

  ```
  // __handlers__/TelegramUI/_S10TelegramUI15openExternalUrl7_b1a3234e.js
  
  onEnter: function (log, args, state) {
  
      log("TelegramUI.openExternalUrl(account, url, presentationData," +
                  "applicationContext, navigationController, dismissInput)");
      log("\taccount: " + ObjC.Object(args[1]).toString());
      log("\turl: " + ObjC.Object(args[2]).toString());
      log("\tpresentationData: " + args[3]);
      log("\tapplicationContext: " + ObjC.Object(args[4]).toString());
      log("\tnavigationController: " + ObjC.Object(args[5]).toString());
  },
  ```

下次运行它时，我们会看到以下输出：

```
$ frida-trace -U Telegram -m "*[* *restorationHandler*]" -i "*open*Url*"
    -m "*[* *application*URL*]" -m "*[* openURL]"

  8144 ms  -[UIApplication _applicationOpenURLAction: 0x1c44ff900 payload: 0x10c5ee4c0 origin: 0x0]
  8145 ms     | -[AppDelegate application: 0x105a59980 openURL: 0x1c46ebb80 options: 0x1c0e222c0]
  8145 ms     |     application: <Application: 0x105a59980>
  8145 ms     |     openURL: tg://resolve?domain=fridadotre
  8145 ms     |     options :{
                        UIApplicationOpenURLOptionsOpenInPlaceKey = 0;
                        UIApplicationOpenURLOptionsSourceApplicationKey = "com.apple.mobilesafari";
                    }
  8269 ms     |    | TelegramUI.openExternalUrl(account, url, presentationData,
                                        applicationContext, navigationController, dismissInput)
  8269 ms     |    |    account: nil
  8269 ms     |    |    url: tg://resolve?domain=fridadotre
  8269 ms     |    |    presentationData: 0x1c4c51741
  8269 ms     |    |    applicationContext: nil
  8269 ms     |    |    navigationController: TelegramUI.PresentationData
  8274 ms     | -[UIApplication applicationOpenURL:0x1c46ebb80]
```

在那里您可以观察到以下内容：

- `application:openURL:options:`它按预期从应用程序委托调用。
- 源应用程序是 Safari（“com.apple.mobilesafari”）。
- `application:openURL:options:`处理 URL 但不打开它，它要求`TelegramUI.openExternalUrl`这样做。
- 正在打开的 URL 是`tg://resolve?domain=fridadotre`。
- 它使用`tg://`来自 Telegram 的自定义 URL 方案。

有趣的是，如果您再次导航到“ https://telegram.me/fridadotre ”，点击**取消**，然后点击页面本身提供的链接（“在 Telegram 应用程序中打开”），而不是打开通过自定义 URL 方案，它将通过通用链接打开。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/open_in_telegram_via_universallink.png)

您可以在跟踪这两种方法时尝试这样做：

```
$ frida-trace -U Telegram -m "*[* *restorationHandler*]" -m "*[* *application*openURL*options*]"

// After clicking "Open" on the pop-up

 16374 ms  -[AppDelegate application :0x10556b3c0 openURL :0x1c4ae0080 options :0x1c7a28400]
 16374 ms   application :<Application: 0x10556b3c0>
 16374 ms   openURL :tg://resolve?domain=fridadotre
 16374 ms   options :{
    UIApplicationOpenURLOptionsOpenInPlaceKey = 0;
    UIApplicationOpenURLOptionsSourceApplicationKey = "com.apple.mobilesafari";
}

// After clicking "Cancel" on the pop-up and "OPEN" in the page

406575 ms  -[AppDelegate application:0x10556b3c0 continueUserActivity:0x1c063d0c0
                restorationHandler:0x16f27a898]
406575 ms  application:<Application: 0x10556b3c0>
406575 ms  continueUserActivity:<NSUserActivity: 0x1c063d0c0>
406575 ms       webpageURL:https://telegram.me/fridadotre
406575 ms       activityType:NSUserActivityTypeBrowsingWeb
406575 ms       userInfo:{
}
406575 ms  restorationHandler:<__NSStackBlock__: 0x16f27a898>
```

##### 测试已弃用的方法[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-for-deprecated-methods_1)

搜索已弃用的方法，例如：

- [`application:handleOpenURL:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1622964-application?language=objc)
- [`openURL:`](https://developer.apple.com/documentation/uikit/uiapplication/1622961-openurl?language=objc)
- [`application:openURL:sourceApplication:annotation:`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623073-application)

您可以为此简单地使用 frida-trace，以查看是否正在使用这些方法中的任何一种。

#### 测试 URL 方案源验证[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-url-schemes-source-validation)

一种丢弃或确认验证的方法是Hook可能用于该验证的典型方法。例如[`isEqualToString:`](https://developer.apple.com/documentation/foundation/nsstring/1407803-isequaltostring)：

```
// - (BOOL)isEqualToString:(NSString *)aString;

var isEqualToString = ObjC.classes.NSString["- isEqualToString:"];

Interceptor.attach(isEqualToString.implementation, {
  onEnter: function(args) {
    var message = ObjC.Object(args[2]);
    console.log(message)
  }
});
```

如果我们应用这个钩子并再次调用 URL scheme：

```
$ frida -U iGoat-Swift

[iPhone::iGoat-Swift]-> var isEqualToString = ObjC.classes.NSString["- isEqualToString:"];

                    Interceptor.attach(isEqualToString.implementation, {
                      onEnter: function(args) {
                        var message = ObjC.Object(args[2]);
                        console.log(message)
                      }
                    });
{}
[iPhone::iGoat-Swift]-> openURL("iGoat://?contactNumber=123456789&message=hola")
true
nil
```

什么都没发生。这已经告诉我们这个方法没有被用于那个，因为我们找不到任何类似*应用程序包的*字符串，比如钩子`OWASP.iGoat-Swift`和`com.apple.mobilesafari`推文文本之间。但是，考虑到我们只是在探索一种方法，应用程序可能正在使用其他方法进行比较。

#### 模糊 URL 方案[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#fuzzing-url-schemes)

如果应用程序解析了部分 URL，您还可以执行输入模糊测试以检测内存损坏错误。

我们上面学到的知识现在可以用来根据您选择的语言构建您自己的模糊器，例如在 Python 中，并`openURL`使用[Frida 的 RPC](https://www.frida.re/docs/javascript-api/#rpc)调用。该模糊器应该执行以下操作：

- 生成有效载荷。
- 为他们每个人打电话`openURL`。
- 检查应用程序是否`.ips`在`/private/var/mobile/Library/Logs/CrashReporter`.

[FuzzDB](https://github.com/fuzzdb-project/fuzzdb)项目提供了可用作负载的模糊测试字典。

##### 使用Frida[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#using-frida_1)

使用 Frida 执行此操作非常简单，您可以参考这篇[博](https://grepharder.github.io/blog/0x03_learning_about_universal_links_and_fuzzing_url_schemes_on_ios_with_frida.html)文以查看对[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)应用程序（在 iOS 11.1.2 上运行）进行模糊测试的示例。

在运行模糊器之前，我们需要将 URL 方案作为输入。从静态分析我们知道[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)应用程序支持以下 URL 方案和参数：`iGoat://?contactNumber={0}&message={0}`.

```
$ frida -U SpringBoard -l ios-url-scheme-fuzzing.js
[iPhone::SpringBoard]-> fuzz("iGoat", "iGoat://?contactNumber={0}&message={0}")
Watching for crashes from iGoat...
No logs were moved.
Opened URL: iGoat://?contactNumber=0&message=0
OK!
Opened URL: iGoat://?contactNumber=1&message=1
OK!
Opened URL: iGoat://?contactNumber=-1&message=-1
OK!
Opened URL: iGoat://?contactNumber=null&message=null
OK!
Opened URL: iGoat://?contactNumber=nil&message=nil
OK!
Opened URL: iGoat://?contactNumber=99999999999999999999999999999999999
&message=99999999999999999999999999999999999
OK!
Opened URL: iGoat://?contactNumber=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
&message=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
OK!
Opened URL: iGoat://?contactNumber=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
&message=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
OK!
Opened URL: iGoat://?contactNumber='&message='
OK!
Opened URL: iGoat://?contactNumber=%20d&message=%20d
OK!
Opened URL: iGoat://?contactNumber=%20n&message=%20n
OK!
Opened URL: iGoat://?contactNumber=%20x&message=%20x
OK!
Opened URL: iGoat://?contactNumber=%20s&message=%20s
OK!
```

该脚本将检测是否发生了崩溃。在这次运行中，它没有检测到任何崩溃，但对于其他应用程序，情况可能是这样。如果它被脚本移动，`/private/var/mobile/Library/Logs/CrashReporter`我们将能够检查崩溃报告。`/tmp`

## 测试 iOS WebViews (MSTG-PLATFORM-5)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-ios-webviews-mstg-platform-5)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_6)

WebView 是用于显示交互式 Web 内容的应用程序内浏览器组件。它们可用于将 Web 内容直接嵌入到应用程序的用户界面中。iOS WebView 默认支持 JavaScript 执行，因此脚本注入和跨站点脚本攻击会影响它们。

#### 界面网页视图[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#uiwebview)

[`UIWebView`](https://developer.apple.com/reference/uikit/uiwebview)从 iOS 12 开始不推荐使用，不应使用。确保使用`WKWebView`或`SFSafariViewController`来嵌入网页内容。除此之外，无法禁用 JavaScript，`UIWebView`这是避免使用它的另一个原因。

#### WKWebView[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#wkwebview)

[`WKWebView`](https://developer.apple.com/reference/webkit/wkwebview)随 iOS 8 引入，是扩展应用程序功能、控制显示内容（即防止用户导航到任意 URL）和自定义的合适选择。`WKWebView`还通过 Nitro JavaScript 引擎 [#thiel2] 显着提高了使用 WebView 的应用程序的性能。

`WKWebView`具有多项安全优势`UIWebView`：

- 默认情况下启用 JavaScript，但由于 的`javaScriptEnabled`属性`WKWebView`，它可以完全禁用，从而防止所有脚本注入缺陷。
- 可`JavaScriptCanOpenWindowsAutomatically`用于防止 JavaScript 打开新窗口，例如弹出窗口。
- 该`hasOnlySecureContent`属性可用于验证 WebView 加载的资源是否通过加密连接检索。
- `WKWebView`实现进程外渲染，因此内存损坏错误不会影响主应用程序进程。

`WKWebView`使用s（和`UIWebView`s）时可以启用 JavaScript Bridge 。有关详细信息，请参阅下面的“[确定Native方法是否通过 WebView 公开](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#determining-whether-native-methods-are-exposed-through-webviews-mstg-platform-7)”部分。

#### SFSafariViewController[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#sfsafariviewcontroller)

[`SFSafariViewController`](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller)从 iOS 9 开始可用，应该用于提供通用的 Web 查看体验。这些 WebView 很容易被发现，因为它们具有包含以下元素的特征布局：

- 带有安全指示器的只读地址字段。
- 一个动作（“分享”）按钮。
- 一个完成按钮、后退和前进导航按钮，以及一个用于直接在 Safari 中打开页面的“Safari”按钮。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/sfsafariviewcontroller.png)

有几件事需要考虑：

- 无法在其中禁用 JavaScript ，这是在目标是扩展应用程序的用户界面时建议`SFSafariViewController`使用 的原因之一。`WKWebView`
- `SFSafariViewController`还与 Safari 共享 cookie 和其他网站数据。
- 用户的活动和与 a 的交互`SFSafariViewController`对应用程序不可见，应用程序无法访问自动填充数据、浏览历史记录或网站数据。
- 根据 App Store 审核指南，`SFSafariViewController`s 不得被其他视图或图层隐藏或遮挡。

这对于应用程序分析应该足够了，因此，`SFSafariViewController`s 超出了静态和动态分析部分的范围。

#### Safari Web 检查器[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#safari-web-inspector)

在 iOS 上启用 Safari web 检查允许您从 macOS 设备远程检查 WebView 的内容，它不需要越狱的 iOS 设备。启用[Safari Web 检查器](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/Safari_Developer_Guide/GettingStarted/GettingStarted.html)对于使用 JavaScript 桥公开Native API 的应用程序特别有趣，例如在混合应用程序中。

要激活网络检查，您必须执行以下步骤：

1. 在 iOS 设备上打开设置应用程序：转到**Safari -> Advanced**并打开*Web Inspector*。
2. 在 macOS 设备上，打开 Safari：在菜单栏中，转到**Safari -> Preferences -> Advanced**并启用*Show Develop menu in menu bar*。
3. 将您的 iOS 设备连接到 macOS 设备并解锁：iOS 设备名称应出现在“*开发*”菜单中。
4. （如果尚未信任）在 macOS 的 Safari 上，转到“*开发*”菜单，单击 iOS 设备名称，然后单击“用于开发”并启用信任。

要打开 Web 检查器并调试 WebView：

1. 在 iOS 中，打开应用程序并导航到应包含 WebView 的屏幕。
2. 在 macOS Safari 中，转到**Developer -> 'iOS Device Name'**，您应该会看到基于 WebView 的上下文的名称。单击它以打开 Web 检查器。

现在，您可以像在桌面浏览器上调试常规网页一样调试 WebView。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_6)

对于静态分析，我们将主要关注范围内的以下`UIWebView`几点`WKWebView`。

- 识别 WebView 使用情况
- 测试 JavaScript 配置
- 测试混合内容
- 测试 WebView URI 操作

#### 识别 WebView 使用情况[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#identifying-webview-usage)

通过在 Xcode 中搜索来查找上述 WebView 类的用法。

在已编译的二进制文件中，您可以像这样搜索其符号或字符串：

##### 界面网页视图[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#uiwebview_1)

```
$ rabin2 -zz ./WheresMyBrowser | egrep "UIWebView$"
489 0x0002fee9 0x10002fee9   9  10 (5.__TEXT.__cstring) ascii UIWebView
896 0x0003c813 0x0003c813  24  25 () ascii @_OBJC_CLASS_$_UIWebView
1754 0x00059599 0x00059599  23  24 () ascii _OBJC_CLASS_$_UIWebView
```

##### WKWEBVIEW[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#wkwebview_1)

```
$ rabin2 -zz ./WheresMyBrowser | egrep "WKWebView$"
490 0x0002fef3 0x10002fef3   9  10 (5.__TEXT.__cstring) ascii WKWebView
625 0x00031670 0x100031670  17  18 (5.__TEXT.__cstring) ascii unwindToWKWebView
904 0x0003c960 0x0003c960  24  25 () ascii @_OBJC_CLASS_$_WKWebView
1757 0x000595e4 0x000595e4  23  24 () ascii _OBJC_CLASS_$_WKWebView
```

或者，您也可以搜索这些 WebView 类的已知方法。例如，搜索用于初始化 WKWebView( [`init(frame:configuration:)`](https://developer.apple.com/documentation/webkit/wkwebview/1414998-init)) 的方法：

```
$ rabin2 -zzq ./WheresMyBrowser | egrep "WKWebView.*frame"
0x5c3ac 77 76 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfC
0x5d97a 79 78 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO
0x6b5d5 77 76 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfC
0x6c3fa 79 78 __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO
```

你也可以 demangle 它：

```
$ xcrun swift-demangle __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO

---> @nonobjc __C.WKWebView.init(frame: __C_Synthesized.CGRect,
                                configuration: __C.WKWebViewConfiguration) -> __C.WKWebView
```

#### 测试 JavaScript 配置[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-javascript-configuration)

首先，请记住不能为`UIWebVIews`.

对于`WKWebView`s，作为最佳实践，除非明确要求，否则应禁用 JavaScript。要验证 JavaScript 是否已正确禁用，请在项目中搜索 usages 的用法`WKPreferences`并确保该[`javaScriptEnabled`](https://developer.apple.com/documentation/webkit/wkpreferences/1536203-javascriptenabled)属性设置为`false`：

```
let webPreferences = WKPreferences()
webPreferences.javaScriptEnabled = false
```

如果只有编译后的二进制文件，您可以在其中搜索：

```
$ rabin2 -zz ./WheresMyBrowser | grep -i "javascriptenabled"
391 0x0002f2c7 0x10002f2c7  17  18 (4.__TEXT.__objc_methname) ascii javaScriptEnabled
392 0x0002f2d9 0x10002f2d9  21  22 (4.__TEXT.__objc_methname) ascii setJavaScriptEnabled:
```

如果定义了用户脚本，它们将继续运行，因为该`javaScriptEnabled`属性不会影响它们。[有关将用户脚本注入WKWebViews](https://developer.apple.com/documentation/webkit/wkuserscript)的更多信息，请参阅[WKUserContentController](https://developer.apple.com/documentation/webkit/wkusercontentcontroller)和WKUserScript。

#### 测试混合内容[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-for-mixed-content)

与 s相反`UIWebView`，当使用`WKWebView`s 时，可以检测[混合内容](https://developers.google.com/web/fundamentals/security/prevent-mixed-content/fixing-mixed-content?hl=en)（从 HTTPS 页面加载的 HTTP 内容）。通过使用该方法[`hasOnlySecureContent`](https://developer.apple.com/documentation/webkit/wkwebview/1415002-hasonlysecurecontent)可以验证页面上的所有资源是否已通过安全加密连接加载。来自 [#thiel2] 的示例（参见第 159 和 160 页）使用它来确保仅向用户显示通过 HTTPS 加载的内容，否则会显示警告，告诉用户检测到混合内容。

在编译的二进制文件中：

```
$ rabin2 -zz ./WheresMyBrowser | grep -i "hasonlysecurecontent"

# nothing found
```

在这种情况下，应用程序不会使用它。

此外，如果您有原始源代码或 IPA，您可以检查嵌入的 HTML 文件并验证它们不包含混合内容。在源和内部标签属性中搜索`http://`，但请记住，这可能会产生误报，例如，找到`<a>`包含其`http://`内部`href`属性的锚标签并不总是会出现混合内容问题。[在MDN Web 文档](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content)中了解有关混合内容的更多信息。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_6)

对于动态分析，我们将解决与静态分析相同的问题。

- 枚举 WebView 实例
- 检查是否启用了 JavaScript
- 验证是否只允许安全内容

通过执行动态检测，可以识别 WebView 并在Runtime(运行时)获取它们的所有属性。当您没有原始源代码时，这非常有用。

对于以下示例，我们将继续使用[“我的浏览器在哪里？” ](https://github.com/authenticationfailure/WheresMyBrowser.iOS/)应用程序和 Frida REPL。

#### 枚举 WebView 实例[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#enumerating-webview-instances)

在应用程序中识别出 WebView 后，您可以检查堆以查找我们在上面看到的一个或多个 WebView 的实例。

例如，如果您使用 Frida，您可以通过“ObjC.choose()”检查堆来实现

```
ObjC.choose(ObjC.classes['UIWebView'], {
  onMatch: function (ui) {
    console.log('onMatch: ', ui);
    console.log('URL: ', ui.request().toString());
  },
  onComplete: function () {
    console.log('done for UIWebView!');
  }
});

ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('URL: ', wk.URL().toString());
  },
  onComplete: function () {
    console.log('done for WKWebView!');
  }
});

ObjC.choose(ObjC.classes['SFSafariViewController'], {
  onMatch: function (sf) {
    console.log('onMatch: ', sf);
  },
  onComplete: function () {
    console.log('done for SFSafariViewController!');
  }
});
```

对于`UIWebView`和`WKWebView`WebViews，我们还打印关联的 URL 以完成。

为了确保您能够在堆中找到 WebView 的实例，请务必先导航到您找到的 WebView。在那里，运行上面的代码，例如通过复制到 Frida REPL 中：

```
$ frida -U com.authenticationfailure.WheresMyBrowser

# copy the code and wait ...

onMatch:  <UIWebView: 0x14fd25e50; frame = (0 126; 320 393);
                autoresize = RM+BM; layer = <CALayer: 0x1c422d100>>
URL:  <NSMutableURLRequest: 0x1c000ef00> {
  URL: file:///var/mobile/Containers/Data/Application/A654D169-1DB7-429C-9DB9-A871389A8BAA/
          Library/UIWebView/scenario1.html, Method GET, Headers {
    Accept =     (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    );
    "Upgrade-Insecure-Requests" =     (
        1
    );
    "User-Agent" =     (
        "Mozilla/5.0 (iPhone; CPU iPhone ... AppleWebKit/604.3.5 (KHTML, like Gecko) Mobile/..."
    );
} }
```

现在我们退出`q`并打开另一个 WebView（`WKWebView`在本例中）。如果我们重复前面的步骤，它也会被检测到：

```
$ frida -U com.authenticationfailure.WheresMyBrowser

# copy the code and wait ...

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>
URL:  file:///var/mobile/Containers/Data/Application/A654D169-1DB7-429C-9DB9-A871389A8BAA/
            Library/WKWebView/scenario1.html
```

我们将在以下部分中扩展此示例，以便从 WebView 获取更多信息。我们建议将此代码存储到一个文件中，例如 webviews_inspector.js 并像这样运行它：

```
frida -U com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js
```

#### 检查 JavaScript 是否已启用[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-if-javascript-is-enabled)

请记住，如果`UIWebView`正在使用 a，则默认情况下会启用 JavaScript，并且无法禁用它。

对于`WKWebView`，您应该验证是否启用了 JavaScript。为此使用[`javaScriptEnabled`](https://developer.apple.com/documentation/webkit/wkpreferences/1536203-javascriptenabled)from 。`WKPreferences`

使用以下行扩展先前的脚本：

```
ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('javaScriptEnabled:', wk.configuration().preferences().javaScriptEnabled());
//...
  }
});
```

输出现在显示，事实上，JavaScript 已启用：

```
$ frida -U com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>

javaScriptEnabled:  true
```

#### 验证是否只允许安全内容[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#verifying-that-only-secure-content-is-allowed)

`UIWebView`没有为此提供方法。但是，您可以通过调用`request`每个`UIWebView`实例的方法来检查系统是否启用了“Upgrade-Insecure-Requests”CSP（内容安全策略）指令（“Upgrade-Insecure-Requests”[应该从 iOS 10 开始可用，](https://www.thesslstore.com/blog/ios-10-will-support-upgrade-insecure-requests/)其中包括一个新的WebKit 版本，支持 iOS WebViews 的浏览器引擎）。请参阅上一节“[枚举 WebView 实例](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#enumerating-webview-instances)”中的示例。

对于s，您可以为在堆中找到的每个s`WKWebView`调用该方法。请记住在 WebView 加载后执行此操作。[`hasOnlySecureContent`](https://developer.apple.com/documentation/webkit/wkwebview/1415002-hasonlysecurecontent)`WKWebView`

使用以下行扩展先前的脚本：

```
ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('hasOnlySecureContent: ', wk.hasOnlySecureContent().toString());
    //...
      }
    });
```

输出显示页面上的某些资源已通过不安全的连接加载：

```
$ frida -U com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>

hasOnlySecureContent:  false
```

#### 测试 WebView URI 操作[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-for-webview-uri-manipulation)

确保 WebView 的 URI 不能被用户操纵，以加载 WebView 运行所必需的其他类型的资源。当 WebView 的内容是从本地文件系统加载时，这可能特别危险，允许用户导航到应用程序中的其他资源。

## 测试 WebView 协议处理程序 (MSTG-PLATFORM-6)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-webview-protocol-handlers-mstg-platform-6)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_7)

在 iOS 上的 WebView 中可以解释几种默认方案，例如：

- http(s)://
- 文件：//
- 电话：//

WebView 可以从端点加载远程内容，但它们也可以从应用程序数据目录加载本地内容。如果加载本地内容，用户不应该能够影响文件名或用于加载文件的路径，并且用户不应该能够编辑加载的文件。

使用以下最佳实践作为纵深防御措施：

- 创建一个列表，定义允许加载的本地和远程网页和 URL 方案。
- 创建本地 HTML/JavaScript 文件的校验和，并在应用程序启动时检查它们。[缩小JavaScript 文件](https://en.wikipedia.org/wiki/Minification_(programming))“缩小（编程）”），使它们更难阅读。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_7)

- 测试 WebView 的加载方式
- 测试 WebView 文件访问
- 检查电话号码检测

#### 测试 WebView 的加载方式[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-how-webviews-are-loaded)

如果 WebView 正在从应用程序数据目录加载内容，则用户不应该能够更改文件名或从中加载文件的路径，并且他们不应该能够编辑加载的文件。

这会带来一个问题，尤其是在`UIWebView`通过已弃用的方法加载不受信任的内容[`loadHTMLString:baseURL:`](https://developer.apple.com/documentation/uikit/uiwebview/1617979-loadhtmlstring?language=objc)或[`loadData:MIMEType:textEncodingName: baseURL:`](https://developer.apple.com/documentation/uikit/uiwebview/1617941-loaddata?language=objc)将`baseURL`参数设置为 URL 方案`nil`或将参数设置`file:`为`applewebdata:`URL 方案时。在这种情况下，为了防止未经授权访问本地文件，最好的选择是将其设置为`about:blank`. 但是，建议避免使用`UIWebView`s 而改用`WKWebView`s。

[这是“我的浏览器在哪里？”](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/master/WheresMyBrowser/UIWebViewController.swift#L219)`UIWebView`中的一个漏洞示例。:

```
let scenario2HtmlPath = Bundle.main.url(forResource: "web/UIWebView/scenario2.html", withExtension: nil)
do {
    let scenario2Html = try String(contentsOf: scenario2HtmlPath!, encoding: .utf8)
    uiWebView.loadHTMLString(scenario2Html, baseURL: nil)
} catch {}
```

该页面使用 HTTP 从 Internet 加载资源，使潜在的 MITM 能够泄露包含在本地文件中的秘密，例如Shared Preferences中的秘密。

使用`WKWebView`s 时，Apple 建议使用[`loadHTMLString:baseURL:`](https://developer.apple.com/documentation/webkit/wkwebview/1415004-loadhtmlstring?language=objc)or[`loadData:MIMEType:textEncodingName:baseURL:`](https://developer.apple.com/documentation/webkit/wkwebview/1415011-loaddata?language=objc)加载本地 HTML 文件和`loadRequest:`Web 内容。通常，本地文件是结合方法加载的，其中包括：[`pathForResource:ofType:`](https://developer.apple.com/documentation/foundation/nsbundle/1410989-pathforresource),[`URLForResource:withExtension:`](https://developer.apple.com/documentation/foundation/nsbundle/1411540-urlforresource?language=objc)或[`init(contentsOf:encoding:)`](https://developer.apple.com/documentation/swift/string/3126736-init).

搜索上述方法的源代码并检查它们的参数。

Objective-C 中的示例：

```
- (void)viewDidLoad
{
    [super viewDidLoad];
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];

    self.webView = [[WKWebView alloc] initWithFrame:CGRectMake(10, 20,
        CGRectGetWidth([UIScreen mainScreen].bounds) - 20,
        CGRectGetHeight([UIScreen mainScreen].bounds) - 84) configuration:configuration];
    self.webView.navigationDelegate = self;
    [self.view addSubview:self.webView];

    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"example_file" ofType:@"html"];
    NSString *html = [NSString stringWithContentsOfFile:filePath
                                encoding:NSUTF8StringEncoding error:nil];
    [self.webView loadHTMLString:html baseURL:[NSBundle mainBundle].resourceURL];
}
```

[来自“我的浏览器在哪里？”的](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/master/WheresMyBrowser/WKWebViewController.swift#L196)Swift 示例 :

```
let scenario2HtmlPath = Bundle.main.url(forResource: "web/WKWebView/scenario2.html", withExtension: nil)
do {
    let scenario2Html = try String(contentsOf: scenario2HtmlPath!, encoding: .utf8)
    wkWebView.loadHTMLString(scenario2Html, baseURL: nil)
} catch {}
```

如果只有编译好的二进制文件，你也可以搜索这些方法，例如：

```
$ rabin2 -zz ./WheresMyBrowser | grep -i "loadHTMLString"
231 0x0002df6c 24 (4.__TEXT.__objc_methname) ascii loadHTMLString:baseURL:
```

在这种情况下，建议进行动态分析，以确保确实在使用它以及来自哪种 WebView。此处的`baseURL`参数不会出现问题，因为它将设置为“null”，但如果在使用`UIWebView`. 有关此的示例，请参阅“检查 WebView 的加载方式”。

此外，您还应该验证应用程序是否正在使用该方法[`loadFileURL: allowingReadAccessToURL:`](https://developer.apple.com/documentation/webkit/wkwebview/1414973-loadfileurl?language=objc)。它的第一个参数是`URL`并且包含要在 WebView 中加载的 URL，它的第二个参数`allowingReadAccessToURL`可能包含单个文件或目录。如果包含单个文件，则该文件将可用于 WebView。但是，如果它包含一个目录，则该目录中的所有文件都将对 WebView 可用。因此，值得对此进行检查，如果它是一个目录，请确认其中没有敏感数据。

[来自“我的浏览器在哪里？”的](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/master/WheresMyBrowser/WKWebViewController.swift#L186)Swift 示例 :

```
var scenario1Url = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
scenario1Url = scenario1Url.appendingPathComponent("WKWebView/scenario1.html")
wkWebView.loadFileURL(scenario1Url, allowingReadAccessTo: scenario1Url)
```

在这种情况下，参数`allowingReadAccessToURL`包含单个文件“WKWebView/scenario1.html”，这意味着 WebView 具有对该文件的独占访问权限。

在编译的二进制文件中：

```
$ rabin2 -zz ./WheresMyBrowser | grep -i "loadFileURL"
237 0x0002dff1 37 (4.__TEXT.__objc_methname) ascii loadFileURL:allowingReadAccessToURL:
```

#### 测试 WebView 文件访问[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-webview-file-access)

如果您发现`UIWebView`正在使用，则适用以下内容：

- 该`file://`方案始终处于启用状态。
- 从`file://`URL 访问文件始终处于启用状态。
- 来自 URL 的通用访问`file://`始终处于启用状态。

关于小号`WKWebView`：

- 该`file://`方案也始终处于启用状态，**无法禁用**。
- 它默认禁用从`file://`URL 访问文件，但可以启用。

以下 WebView 属性可用于配置文件访问：

- `allowFileAccessFromFileURLs`( `WKPreferences`，`false`默认情况下)：它使在`file://`方案 URL 上下文中运行的 JavaScript 能够访问来自其他`file://`方案 URL 的内容。
- `allowUniversalAccessFromFileURLs`( `WKWebViewConfiguration`，`false`默认情况下)：它使在`file://`方案 URL 的上下文中运行的 JavaScript 能够访问来自任何来源的内容。

例如，可以通过这样做来设置**[未记录的属性：](https://github.com/WebKit/webkit/blob/master/Source/WebKit/UIProcess/API/Cocoa/WKPreferences.mm#L470)** `allowFileAccessFromFileURLs`

Objective-C：

```
[webView.configuration.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];
```

Swift:

```
webView.configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
```

如果激活了上述一个或多个属性，您应该确定它们是否真的是应用程序正常运行所必需的。

#### 检查电话号码检测[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-telephone-number-detection)

在 iOS 上的 Safari 中，电话号码检测默认处于启用状态。但是，如果您的 HTML 页面包含可以解释为电话号码但不是电话号码的数字，或者为了防止 DOM 文档在浏览器解析时被修改，您可能希望将其关闭。要在 iOS 上的 Safari 中关闭电话号码检测，请使用格式检测元标记 ( `<meta name = "format-detection" content = "telephone=no">`)。可以在[Apple 开发人员文档](https://developer.apple.com/library/archive/featuredarticles/iPhoneURLScheme_Reference/PhoneLinks/PhoneLinks.html#//apple_ref/doc/uid/TP40007899-CH6-SW2)中找到这方面的示例。然后应使用电话链接（例如`<a href="tel:1-408-555-5555">1-408-555-5555</a>`）明确创建链接。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_7)

如果可以通过 WebView 加载本地文件，应用程序可能容易受到目录遍历攻击。这将允许访问沙箱内的所有文件，甚至可以通过对文件系统的完全访问来逃脱沙箱（如果设备已越狱）。因此，应该验证用户是否可以更改加载文件的文件名或路径，并且他们不应该能够编辑加载的文件。

要模拟攻击，您可以使用拦截代理或简单地使用动态检测将您自己的 JavaScript 注入到 WebView 中。尝试访问本地存储以及可能暴露给 JavaScript 上下文的任何Native方法和属性。

在现实世界中，JavaScript 只能通过永久后端跨站点脚本漏洞或 MITM 攻击来注入。有关详细信息，请参阅 OWASP [XSS 预防备忘单](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)和“ [iOS 网络通信](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/)”一章。

对于本节所涉及的内容，我们将了解：

- 检查 WebView 的加载方式
- 确定 WebView 文件访问

#### 检查 WebView 的加载方式[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#checking-how-webviews-are-loaded)

正如我们在上面“测试 WebViews 的加载方式”中看到的那样，如果加载了 WKWebViews 的“场景 2”，应用程序将通过调用[`URLForResource:withExtension:`](https://developer.apple.com/documentation/foundation/nsbundle/1411540-urlforresource?language=objc)和来完成`loadHTMLString:baseURL`。

要快速检查这一点，您可以使用 frida-trace 并跟踪所有“loadHTMLString”和“URLForResource:withExtension:”方法。

```
$ frida-trace -U "Where's My Browser?"
    -m "*[WKWebView *loadHTMLString*]" -m "*[* URLForResource:withExtension:]"

 14131 ms  -[NSBundle URLForResource:0x1c0255390 withExtension:0x0]
 14131 ms  URLForResource: web/WKWebView/scenario2.html
 14131 ms  withExtension: 0x0
 14190 ms  -[WKWebView loadHTMLString:0x1c0255390 baseURL:0x0]
 14190 ms   HTMLString: <!DOCTYPE html>
    <html>
        ...
        </html>

 14190 ms  baseURL: nil
```

在本例中，`baseURL`设置为`nil`，表示有效原点为“空”。您可以通过从页面的 JavaScript 运行来获取有效来源`window.origin`（此应用程序有一个允许编写和运行 JavaScript 的开发帮助程序，但您也可以实施 MITM 或简单地使用 Frida 注入 JavaScript，例如通过`evaluateJavaScript:completionHandler`of `WKWebView`）。

作为关于 s 的附加说明，如果您从也设置为的where`UIWebView`检索有效来源，您将看到它未设置为“null”，而是您将获得类似于以下内容的内容：`UIWebView``baseURL``nil`

```
applewebdata://5361016c-f4a0-4305-816b-65411fc1d780
```

此源“applewebdata://”类似于“file://”源，因为它不实施同源策略并允许访问本地文件和任何网络资源。在这种情况下，最好设置`baseURL`为“about:blank”，这样同源策略就可以防止跨域访问。但是，这里的建议是完全避免使用`UIWebView`s 而改用 for `WKWebView`s。

#### 确定 WebView 文件访问[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#determining-webview-file-access)

即使没有原始源代码，您也可以快速确定应用程序的 WebView 是否允许文件访问以及哪种类型。为此，只需导航到应用程序中的目标 WebView 并检查其所有实例，对于它们中的每一个都获取静态分析中提到的值，即`allowFileAccessFromFileURLs`和`allowUniversalAccessFromFileURLs`。这仅适用于`WKWebView`s（`UIWebVIew`s 始终允许文件访问）。

我们使用[“我的浏览器在哪里？”继续我们的例子。](https://github.com/authenticationfailure/WheresMyBrowser.iOS/)app 和 Frida REPL，使用以下内容扩展脚本：

```
ObjC.choose(ObjC.classes['WKWebView'], {
  onMatch: function (wk) {
    console.log('onMatch: ', wk);
    console.log('URL: ', wk.URL().toString());
    console.log('javaScriptEnabled: ', wk.configuration().preferences().javaScriptEnabled());
    console.log('allowFileAccessFromFileURLs: ',
            wk.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs').toString());
    console.log('hasOnlySecureContent: ', wk.hasOnlySecureContent().toString());
    console.log('allowUniversalAccessFromFileURLs: ',
            wk.configuration().valueForKey_('allowUniversalAccessFromFileURLs').toString());
  },
  onComplete: function () {
    console.log('done for WKWebView!');
  }
});
```

如果您现在运行它，您将获得所需的所有信息：

```
$ frida -U -f com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js

onMatch:  <WKWebView: 0x1508b1200; frame = (0 0; 320 393); layer = <CALayer: 0x1c4238f20>>
URL:  file:///var/mobile/Containers/Data/Application/A654D169-1DB7-429C-9DB9-A871389A8BAA/
        Library/WKWebView/scenario1.html
javaScriptEnabled:  true
allowFileAccessFromFileURLs:  0
hasOnlySecureContent:  false
allowUniversalAccessFromFileURLs:  0
```

`allowFileAccessFromFileURLs`和都`allowUniversalAccessFromFileURLs`设置为“0”，表示它们被禁用。在这个应用程序中，我们可以转到 WebView 配置并启用`allowFileAccessFromFileURLs`. 如果我们这样做并重新运行脚本，我们将看到这次它是如何设置为“1”的：

```
$ frida -U -f com.authenticationfailure.WheresMyBrowser -l webviews_inspector.js
...

allowFileAccessFromFileURLs:  1
```

## 确定Native方法是否通过 WebView 公开 (MSTG-PLATFORM-7)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#determining-whether-native-methods-are-exposed-through-webviews-mstg-platform-7)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_8)

从 iOS 7 开始，Apple 引入了 API，允许 WebView 中的 JavaScript Runtime(运行时)与Native Swift 或 Objective-C 对象之间进行通信。如果不小心使用这些 API，重要的功能可能会暴露给设法将恶意脚本注入 WebView 的攻击者（例如，通过成功的跨站点脚本攻击）。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_8)

`UIWebView`和都`WKWebView`提供了 WebView 和Native应用程序之间的通信方式。暴露给 WebView JavaScript 引擎的任何重要数据或Native功能也可以被在 WebView 中运行的流氓 JavaScript 访问。

#### 测试 UIWebView JavaScript 到原生桥[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-uiwebview-javascript-to-native-bridges)

Native代码和 JavaScript 如何通信有两种基本方式：

- **JSContext**：当 Objective-C 或 Swift 块被分配给 a 中的标识符时`JSContext`，JavaScriptCore 会自动将块包装在 JavaScript 函数中。
- **JSExport 协议**：在继承协议中声明的属性、实例方法和类方法`JSExport`被映射到可用于所有 JavaScript 代码的 JavaScript 对象。JavaScript 环境中对象的修改会反映在Native环境中。

请注意，`JSExport`JavaScript 代码只能访问协议中定义的类成员。

寻找将Native对象映射到`JSContext`与 WebView 关联的代码，并分析它公开的功能，例如，不应访问敏感数据并将其公开给 WebView。

在 Objective-C 中，`JSContext`关联 a`UIWebView`的获取方式如下：

```
[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]
```

#### 测试 WKWebView JavaScript 到原生桥[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-wkwebview-javascript-to-native-bridges)

a 中的 JavaScript 代码`WKWebView`仍然可以将消息发送回Native应用程序，但相比之下`UIWebView`，无法直接引用`JSContext`a 的`WKWebView`。相反，通信是使用消息系统和函数实现的`postMessage`，该函数会自动将 JavaScript 对象序列化为Native Objective-C 或 Swift 对象。消息处理程序是使用方法配置的[`add(_ scriptMessageHandler:name:)`](https://developer.apple.com/documentation/webkit/wkusercontentcontroller/1537172-add)。

`WKScriptMessageHandler`通过搜索并检查所有公开的方法来验证是否存在 JavaScript 到Native的桥接。然后验证如何调用这些方法。

以下示例来自[“我的浏览器在哪里？” ](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/b8d4abda4000aa509c7a5de79e5c90360d1d0849/WheresMyBrowser/WKWebViewPreferencesManager.swift#L98)证明了这一点。

首先我们看看如何启用 JavaScript 桥：

```
func enableJavaScriptBridge(_ enabled: Bool) {
    options_dict["javaScriptBridge"]?.value = enabled
    let userContentController = wkWebViewConfiguration.userContentController
    userContentController.removeScriptMessageHandler(forName: "javaScriptBridge")

    if enabled {
            let javaScriptBridgeMessageHandler = JavaScriptBridgeMessageHandler()
            userContentController.add(javaScriptBridgeMessageHandler, name: "javaScriptBridge")
    }
}
```

添加具有名称`"name"`（或在上面的示例中）的脚本消息处理程序会导致在使用用户内容控制器的所有 Web 视图的所有框架中定义`"javaScriptBridge"`JavaScript 函数。`window.webkit.messageHandlers.myJavaScriptMessageHandler.postMessage`然后可以[像这样从 HTML 文件](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/d4e2d9efbde8841bf7e4a8800418dda6bb116ec6/WheresMyBrowser/web/WKWebView/scenario3.html#L33)中使用它：

```
function invokeNativeOperation() {
    value1 = document.getElementById("value1").value
    value2 = document.getElementById("value2").value
    window.webkit.messageHandlers.javaScriptBridge.postMessage(["multiplyNumbers", value1, value2]);
}
```

被调用函数驻留在[`JavaScriptBridgeMessageHandler.swift`](https://github.com/authenticationfailure/WheresMyBrowser.iOS/blob/b8d4abda4000aa509c7a5de79e5c90360d1d0849/WheresMyBrowser/JavaScriptBridgeMessageHandler.swift#L29)：

```
class JavaScriptBridgeMessageHandler: NSObject, WKScriptMessageHandler {

//...

case "multiplyNumbers":

        let arg1 = Double(messageArray[1])!
        let arg2 = Double(messageArray[2])!
        result = String(arg1 * arg2)
//...

let javaScriptCallBack = "javascriptBridgeCallBack('\(functionFromJS)','\(result)')"
message.webView?.evaluateJavaScript(javaScriptCallBack, completionHandler: nil)
```

这里的问题是`JavaScriptBridgeMessageHandler`不仅包含那个函数，它还公开了一个敏感函数：

```
case "getSecret":
        result = "XSRSOGKC342"
```

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_8)

至此，您肯定已经确定了 iOS 应用程序中所有可能有趣的 WebView，并大致了解了潜在的攻击面（通过静态分析、我们在前面部分中看到的动态分析技术或它们的组合）。这将包括 HTML 和 JavaScript 文件、`JSContext`/ `JSExport`for`UIWebView`和`WKScriptMessageHandler`for的用法`WKWebView`，以及 WebView 中公开和呈现的函数。

进一步的动态分析可以帮助您利用这些功能并获取它们可能公开的敏感数据。正如我们在静态分析中看到的那样，在前面的示例中，通过执行逆向工程获得秘密值是微不足道的（秘密值是在源代码中的纯文本中找到的）但想象一下暴露的函数从 secure 中检索秘密贮存。在这种情况下，只有动态分析和开发会有所帮助。

利用这些函数的过程从生成 JavaScript 负载并将其注入到应用程序请求的文件中开始。注射可以通过多种技术完成，例如：

- 如果某些内容是通过 HTTP（混合内容）从 Internet 不安全地加载的，您可以尝试实施 MITM 攻击。
- 您始终可以使用 Frida 等框架和适用于 iOS WebView（[`stringByEvaluatingJavaScriptFromString:`](https://developer.apple.com/documentation/uikit/uiwebview/1617963-stringbyevaluatingjavascriptfrom?language=objc)for`UIWebView`和[`evaluateJavaScript:completionHandler:`](https://developer.apple.com/documentation/webkit/wkwebview/1415017-evaluatejavascript?language=objc)for `WKWebView`）的相应 JavaScript 评估函数来执行动态检测并注入 JavaScript 负载。

为了从前面的“我的浏览器在哪里？”的例子中得到秘密。应用程序，您可以使用这些技术之一来注入以下有效负载，通过将其写入 WebView 的“结果”字段来揭示秘密：

```
function javascriptBridgeCallBack(name, value) {
    document.getElementById("result").innerHTML=value;
};
window.webkit.messageHandlers.javaScriptBridge.postMessage(["getSecret"]);
```

当然，你也可以使用它提供的Exploitation Helper：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06h/exploit_javascript_bridge.png)

请参阅 [#thiel2] 第 156 页中暴露给 WebView 的易受攻击的 iOS 应用程序和功能的另一个示例。

## 测试对象持久性 (MSTG-PLATFORM-8)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-object-persistence-mstg-platform-8)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#overview_9)

有几种方法可以在 iOS 上持久化一个对象：

#### 对象编码[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#object-encoding)

iOS 为 Objective-C 或`NSObject`s 提供了两种对象编码和解码协议：`NSCoding`和`NSSecureCoding`. 当一个类符合任一协议时，数据将被序列化为`NSData`：字节缓冲区的包装器。请注意，`Data`在 Swift 中 is the same as `NSData`or its mutable counterpart: `NSMutableData`. 该`NSCoding`协议声明了两个必须实现的方法，以便对其实例变量进行编码/解码。使用的类`NSCoding`需要实现`NSObject`或注释为 @objc 类。该`NSCoding`协议需要实现编码和初始化，如下所示。

```
class CustomPoint: NSObject, NSCoding {

    //required by NSCoding:
    func encode(with aCoder: NSCoder) {
        aCoder.encode(x, forKey: "x")
        aCoder.encode(name, forKey: "name")
    }

    var x: Double = 0.0
    var name: String = ""

    init(x: Double, name: String) {
            self.x = x
            self.name = name
    }

    // required by NSCoding: initialize members using a decoder.
    required convenience init?(coder aDecoder: NSCoder) {
            guard let name = aDecoder.decodeObject(forKey: "name") as? String
                    else {return nil}
            self.init(x:aDecoder.decodeDouble(forKey:"x"),
                                name:name)
    }

    //getters/setters/etc.
}
```

问题`NSCoding`在于，在您可以评估类类型之前，通常已经构造并插入了对象。这使攻击者可以轻松注入各种数据。因此，`NSSecureCoding`引入了该协议。当符合[`NSSecureCoding`](https://developer.apple.com/documentation/foundation/NSSecureCoding)你需要包括：

```
static var supportsSecureCoding: Bool {
        return true
}
```

什么时候`init(coder:)`上课。接下来，在解码对象时，应该进行检查，例如：

```
let obj = decoder.decodeObject(of:MyClass.self, forKey: "myKey")
```

一致性`NSSecureCoding`确保被实例化的对象确实是预期的对象。但是，没有对数据进行额外的完整性检查，并且数据未加密。因此，任何秘密数据都需要额外的加密，必须保护其完整性的数据应该获得额外的 HMAC。

请注意，当使用`NSData`(Objective-C) 或关键字`let`(Swift) 时：数据在内存中是不可变的，并且不能轻易删除。

#### 使用 NSKeyedArchiver 进行对象归档[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#object-archiving-with-nskeyedarchiver)

`NSKeyedArchiver`是 的具体子类，`NSCoder`提供了一种对对象进行编码并将其存储在文件中的方法。`NSKeyedUnarchiver`解码数据并重新创建原始数据。让我们以该`NSCoding`部分为例，现在归档和取消归档它们：

```
// archiving:
NSKeyedArchiver.archiveRootObject(customPoint, toFile: "/path/to/archive")

// unarchiving:
guard let customPoint = NSKeyedUnarchiver.unarchiveObjectWithFile("/path/to/archive") as?
    CustomPoint else { return nil }
```

解码键控存档时，因为值是按名称请求的，所以值可能会乱序解码或根本不解码。因此，键控归档为向前和向后兼容性提供了更好的支持。这意味着磁盘上的存档实际上可能包含程序未检测到的其他数据，除非在稍后阶段提供给定数据的密钥。

请注意，在机密数据的情况下，需要采取额外的保护措施来保护文件，因为文件中的数据未加密。[有关详细信息，请参阅“ iOS 上](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/)的数据存储”一章。

#### 可编码[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#codable)

在 Swift 4 中，`Codable`类型别名出现了：它是`Decodable`和`Encodable`协议的组合。A `String`, `Int`, `Double`, `Date`,`Data`和`URL`是`Codable`本质上的：这意味着它们可以很容易地编码和解码而无需任何额外的工作。让我们来看下面的例子：

```
struct CustomPointStruct:Codable {
    var x: Double
    var name: String
}
```

通过添加到示例中`Codable`的继承列表，自动支持方法和。有关检查[Apple Developer Documentation](https://developer.apple.com/documentation/foundation/archives_and_serialization/encoding_and_decoding_custom_types)工作原理的更多详细信息。可以轻松地将 s 编码/解码为各种表示形式：使用/ 、JSON、属性列表、XML 等。有关详细信息，请参阅下面的小节。`CustomPointStruct``init(from:)``encode(to:)``Codable``Codable``NSData``NSCoding``NSSecureCoding`

#### JSON 和 Codable[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#json-and-codable)

通过使用不同的第 3 方库，可以通过多种方式在 iOS 中编码和解码 JSON：

- [Mantle](https://github.com/Mantle/Mantle)
- [JSON模型库](https://github.com/jsonmodel/jsonmodel)
- [SwiftyJSON 库](https://github.com/SwiftyJSON/SwiftyJSON)
- [ObjectMapper 库](https://github.com/Hearst-DD/ObjectMapper)
- [JSONKit](https://github.com/johnezang/JSONKit)
- [JSON模型](https://github.com/JSONModel/JSONModel)
- [YY型号](https://github.com/ibireme/YYModel)
- [SBJson 5](https://github.com/ibireme/YYModel)
- [开箱](https://github.com/JohnSundell/Unbox)
- [光泽度](https://github.com/hkellaway/Gloss)
- [映射器](https://github.com/lyft/mapper)
- [杰森](https://github.com/delba/JASON)
- [箭](https://github.com/freshOS/Arrow)

这些库在对某些版本的 Swift 和 Objective-C 的支持方面有所不同，无论它们是否返回（不）可变结果、速度、内存消耗和实际库大小。再次注意不变性的情况：机密信息不能轻易从内存中删除。

`Codable`接下来，Apple 通过结合a`JSONEncoder`和 a直接提供对 JSON 编码/解码的支持`JSONDecoder`：

```
struct CustomPointStruct: Codable {
    var point: Double
    var name: String
}

let encoder = JSONEncoder()
encoder.outputFormatting = .prettyPrinted

let test = CustomPointStruct(point: 10, name: "test")
let data = try encoder.encode(test)
let stringData = String(data: data, encoding: .utf8)

// stringData = Optional ({
// "point" : 10,
// "name" : "test"
// })
```

JSON 本身可以存储在任何地方，例如 (NoSQL) 数据库或文件。您只需要确保任何包含秘密的 JSON 都得到了适当的保护（例如，加密/HMACed）。[有关详细信息，请参阅“ iOS 上](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/)的数据存储”一章。

#### 财产清单和 Codable[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#property-lists-and-codable)

您可以将对象持久化到*属性列表*（在前面的部分中也称为 plists）。您可以在下面找到有关如何使用它的两个示例：

```
// archiving:
let data = NSKeyedArchiver.archivedDataWithRootObject(customPoint)
NSUserDefaults.standardUserDefaults().setObject(data, forKey: "customPoint")

// unarchiving:

if let data = NSUserDefaults.standardUserDefaults().objectForKey("customPoint") as? NSData {
    let customPoint = NSKeyedUnarchiver.unarchiveObjectWithData(data)
}
```

在第一个示例中，`NSUserDefaults`使用了 ，这是主要*属性列表*。我们可以对`Codable`版本做同样的事情：

```
struct CustomPointStruct: Codable {
        var point: Double
        var name: String
    }

    var points: [CustomPointStruct] = [
        CustomPointStruct(point: 1, name: "test"),
        CustomPointStruct(point: 2, name: "test"),
        CustomPointStruct(point: 3, name: "test"),
    ]

    UserDefaults.standard.set(try? PropertyListEncoder().encode(points), forKey: "points")
    if let data = UserDefaults.standard.value(forKey: "points") as? Data {
        let points2 = try? PropertyListDecoder().decode([CustomPointStruct].self, from: data)
    }
```

请注意，**`plist`文件并不意味着存储秘密信息**。它们旨在保存用户对应用程序的偏好。

#### XML[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#xml)

有多种方法可以进行 XML 编码。与JSON解析类似，还有各种第三方库，比如：

- [附子](https://github.com/cezheng/Fuzi)
- [小野](https://github.com/mattt/Ono)
- [AEXML](https://github.com/tadija/AEXML)
- [狂喜XML](https://github.com/ZaBlanc/RaptureXML)
- [SwiftyXML 解析器](https://github.com/yahoojapan/SwiftyXMLParser)
- [SWXML散列](https://github.com/drmohundro/SWXMLHash)

它们在速度、内存使用、对象持久性和更重要的方面有所不同：在处理 XML 外部实体的方式上有所不同。以 Apple iOS Office查看器中的[XXE](https://nvd.nist.gov/vuln/detail/CVE-2015-3784)为例。因此，如果可能，禁用外部实体解析是关键。有关详细信息，请参阅[OWASP XXE 预防备忘](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)单。在库（Libraries）旁边，您可以使用 Apple 的[`XMLParser`课程](https://developer.apple.com/documentation/foundation/xmlparser)

当不使用第三方库，而是使用 Apple 的库时，`XMLParser`一定要让`shouldResolveExternalEntities`return `false`。

#### 对象关系映射（CoreData 和 Realm）[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#object-relational-mapping-coredata-and-realm)

iOS 有各种类似 ORM 的解决方案。第一个是[Realm](https://realm.io/docs/swift/latest/)，它有自己的存储引擎。Realm 具有加密数据的设置，如[Realm 文档](https://academy.realm.io/posts/tim-oliver-realm-cocoa-tutorial-on-encryption-with-realm/)中所述。这允许处理安全数据。请注意，默认情况下加密是关闭的。

Apple 自己提供，这在[Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/CoreData/index.html#//apple_ref/doc/uid/TP40001075-CH2-SW1,)`CoreData`中有很好的解释。它支持各种存储后端，如[Apple 的 Persistent Store Types and Behaviors 文档](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/CoreData/PersistentStoreFeatures.html)中所述。Apple 推荐的存储后端的问题是，没有一种数据存储类型是加密的，也没有检查完整性。因此，如果是机密数据，则需要采取额外措施。[在项目 iMas](https://github.com/project-imas/encrypted-core-data)中可以找到一个替代方案，它确实提供开箱即用的加密。

#### 协议缓冲区[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#protocol-buffers)

[Google 的Protocol Buffers](https://developers.google.com/protocol-buffers/)是一种与平台和语言无关的机制，用于通过[二进制数据格式](https://developers.google.com/protocol-buffers/docs/encoding)序列化结构化数据。它们可通过[Protobuf](https://github.com/apple/swift-protobuf)库用于 iOS。Protocol Buffers 存在一些漏洞，例如[CVE-2015-5237](https://www.cvedetails.com/cve/CVE-2015-5237/)。请注意，**Protocol Buffers 不提供任何机密性保护，**因为没有可用的内置加密。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_9)

所有不同风格的对象持久化都有以下问题：

- 如果您使用对象持久性在设备上存储敏感信息，请确保数据已加密：在数据库级别，或者特别是在值级别。
- 需要保证信息的完整性？使用 HMAC 机制或对存储的信息进行签名。在处理存储在对象中的实际信息之前，始终验证 HMAC/签名。
- 确保上述两个概念中使用的密钥安全地存储在 KeyChain 中并受到良好保护。[有关详细信息，请参阅“ iOS 上](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/)的数据存储”一章。
- 确保反序列化对象中的数据在被主动使用之前经过仔细验证（例如，不可能利用业务/应用程序逻辑）。
- 不要使用使用[Runtime(运行时)引用](https://developer.apple.com/library/archive/#documentation/Cocoa/Reference/ObjCRuntimeRef/Reference/reference.html)的持久化机制来序列化/反序列化高风险应用程序中的对象，因为攻击者可能能够通过这种机制操纵步骤来执行业务逻辑（更多信息请参见“ [iOS 反逆向防御](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/)”一章）细节）。
- 请注意，在 Swift 2 及更高版本中，[Mirror](https://developer.apple.com/documentation/swift/mirror)可用于读取对象的一部分，但不能用于对对象进行写入。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_9)

有几种执行动态分析的方法：

- 对于实际的持久性：使用“iOS 上的数据存储”一章中描述的技术。
- 对于序列化本身：使用调试构建或使用 Frida / objection 来查看序列化方法是如何处理的（例如，应用程序是否崩溃或是否可以通过丰富对象来提取额外信息）。

## 测试强制更新 (MSTG-ARCH-9)[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#testing-enforced-updating-mstg-arch-9)

当由于证书/公钥轮换而必须刷新 pin 时，强制更新在涉及公钥固定（有关更多详细信息，请参阅测试网络通信）时非常有用。接下来，漏洞很容易通过强制更新的方式进行修补。然而，iOS 面临的挑战是，Apple 尚未提供任何 API 来自动执行此过程，相反，开发人员将不得不创建自己的机制，例如各种[博客](https://mobikul.com/show-update-application-latest-version-functionality-ios-app-swift-3/)中描述的，归结为使用`http://itunes.apple.com/lookup\?id\<BundleId>`或第三方查找应用程序的属性派对库，例如[Siren](https://github.com/ArtSabintsev/Siren)和[react-native-appstore-version-checker](https://www.npmjs.com/package/react-native-appstore-version-checker). 这些实现中的大多数将需要 API 提供的特定给定版本或只是“应用商店中的最新版本”，这意味着用户可能会对必须更新应用程序感到沮丧，即使实际上没有业务/安全需要更新。

请注意，较新版本的应用程序不会修复存在于应用程序与之通信的后端中的安全问题。允许应用程序不与其通信可能还不够。拥有适当的 API 生命周期管理是这里的关键。同样，当用户没有被迫更新时，不要忘记根据您的 API 测试您应用程序的旧版本和/或使用适当的 API 版本控制。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#static-analysis_10)

首先查看是否有更新机制：如果还没有，则可能意味着无法强制用户更新。如果存在该机制，请查看它是否强制执行“始终最新”以及这是否确实符合业务策略。否则检查该机制是否支持更新到给定版本。确保应用程序的每个条目都经过更新机制，以确保无法绕过更新机制。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#dynamic-analysis_10)

为了测试是否正确更新：尝试下载具有安全漏洞的旧版本应用程序，可以通过开发人员发布的版本或使用第三方应用程序商店。接下来，验证您是否可以在不更新应用程序的情况下继续使用该应用程序。如果给出了更新提示，请通过取消提示或以其他方式通过正常的应用程序使用来规避它来验证您是否仍然可以使用该应用程序。这包括验证后端是否会停止调用易受攻击的后端和/或易受攻击的应用程序版本本身是否被后端阻止。最后，看看您是否可以使用中间人应用程序的版本号，看看后端如何对此做出响应（例如，如果它被记录下来）。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#references)

- [#thiel2] David Thiel，iOS 应用程序安全：黑客和开发人员权威指南（Kindle 位置 3394-3399），No Starch Press，Kindle 版。
- UIWebView 的安全漏洞 - https://medium.com/ios-os-x-development/security-flaw-with-uiwebview-95bbd8508e3c
- 使用 Frida 了解 iOS 上的通用链接和模糊 URL 方案 - https://grepharder.github.io/blog/0x03_learning_about_universal_links_and_fuzzing_url_schemes_on_ios_with_frida.html

### OWASP MASVS[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#owasp-masvs)

- MSTG-ARCH-9：“存在强制更新移动应用程序的机制。”
- MSTG-PLATFORM-1：“该应用程序仅请求必要的最少权限集。”
- MSTG-PLATFORM-3：“该应用程序不会通过自定义 URL 方案导出敏感功能，除非这些机制得到适当保护。”
- MSTG-PLATFORM-4：“该应用程序不会通过 IPC 设施导出敏感功能，除非这些机制得到适当保护。”
- MSTG-PLATFORM-5：“除非明确要求，否则 JavaScript 在 WebView 中被禁用。”
- MSTG-PLATFORM-6：“WebViews 配置为仅允许所需的最小协议处理程序集（理想情况下，仅支持 https）。禁用潜在危险的处理程序，例如文件、电话和应用程序 ID。”
- MSTG-PLATFORM-7：“如果应用程序的Native方法暴露给 WebView，请验证 WebView 仅呈现应用程序包中包含的 JavaScript。”
- MSTG-PLATFORM-8：“对象反序列化（如果有的话）是使用安全序列化 API 实现的。”

### 关于 iOS 中的对象持久化[¶](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/#regarding-object-persistence-in-ios)

- https://developer.apple.com/documentation/foundation/NSSecureCoding
- https://developer.apple.com/documentation/foundation/archives_and_serialization?language=swift
- https://developer.apple.com/documentation/foundation/nskeyedarchiver
- https://developer.apple.com/documentation/foundation/nscoding?language=swift
- https://developer.apple.com/documentation/foundation/NSSecureCoding?language=swift
- https://developer.apple.com/documentation/foundation/archives_and_serialization/encoding_and_decoding_custom_types
- https://developer.apple.com/documentation/foundation/archives_and_serialization/using_json_with_custom_types
- https://developer.apple.com/documentation/foundation/jsonencoder
- https://medium.com/if-let-swift-programming/migrating-to-codable-from-nscoding-ddc2585f28a4
- https://developer.apple.com/documentation/foundation/xmlparser
