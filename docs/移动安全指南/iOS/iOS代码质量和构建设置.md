# iOS 代码质量和构建设置[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#ios-code-quality-and-build-settings)

## 确保应用程序已正确签名 (MSTG-CODE-1)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#making-sure-that-the-app-is-properly-signed-mstg-code-1)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#overview)

[对您的应用程序进行代码签名](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/#code-signing)可向用户保证该应用程序具有已知来源并且自上次签名后未被修改。您的应用在集成应用服务、安装到非越狱设备或提交到应用商店之前，必须使用苹果颁发的证书进行签名。有关如何申请证书和对您的应用程序进行代码签名的更多信息，请查看[App Distribution Guide](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html)。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis)

您必须确保应用程序[使用最新的代码签名格式](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format)。[您可以使用codesign](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)从应用程序的 .app 文件中检索签名证书信息。Codesign用于创建、检查和显示代码签名，以及查询已签名代码在系统中的动态状态。

获取应用程序的 IPA 文件后，将其重新保存为 ZIP 文件并解压缩 ZIP 文件。导航到应用程序的 .app 文件所在的 Payload 目录。

执行以下`codesign`命令显示签名信息：

```
$ codesign -dvvv YOURAPP.app
Executable=/Users/Documents/YOURAPP/Payload/YOURAPP.app/YOURNAME
Identifier=com.example.example
Format=app bundle with Mach-O universal (armv7 arm64)
CodeDirectory v=20200 size=154808 flags=0x0(none) hashes=4830+5 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha1=455758418a5f6a878bb8fdb709ccfca52c0b5b9e
CandidateCDHash sha256=fd44efd7d03fb03563b90037f92b6ffff3270c46
Hash choices=sha1,sha256
CDHash=fd44efd7d03fb03563b90037f92b6ffff3270c46
Signature size=4678
Authority=iPhone Distribution: Example Ltd
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
Signed Time=4 Aug 2017, 12:42:52
Info.plist entries=66
TeamIdentifier=8LAMR92KJ8
Sealed Resources version=2 rules=12 files=1410
Internal requirements count=1 size=176
```

[如Apple 文档](https://developer.apple.com/business/distribute/)中所述，有多种方法可以分发您的应用程序，其中包括使用 App Store 或通过 Apple Business Manager 进行自定义或内部分发。如果是内部分发方案，请确保在为分发签署应用程序时不使用临时证书。

## 确定应用程序是否可调试 (MSTG-CODE-2)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#determining-whether-the-app-is-debuggable-mstg-code-2)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#overview_1)

可以使用 Xcode 调试 iOS 应用程序，它嵌入了一个名为 lldb 的强大调试器。Lldb 是自 Xcode5 以来的默认调试器，它取代了 gdb 等 GNU 工具，并完全集成在开发环境中。虽然在开发应用程序时调试是一项有用的功能，但在将应用程序发布到 App Store 或在企业程序中之前必须关闭它。

在 Build 或 Release 模式下生成应用程序取决于 Xcode 中的构建设置；当在 Debug 模式下生成应用程序时，会在生成的文件中插入 DEBUG 标志。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis_1)

首先，您需要确定生成应用程序的模式，以检查环境中的标志：

- 选择项目的构建设置
- 在“Apple LVM - Preprocessing”和“Preprocessor Macros”下，确保未选择“DEBUG”或“DEBUG_MODE”（Objective-C）
- 确保未选择“调试可执行文件”选项。
- 或者在“Swift Compiler - Custom Flags”部分/“Other Swift Flags”中，确保“-D DEBUG”条目不存在。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#dynamic-analysis)

检查您是否可以使用 Xcode 直接附加调试器。接下来，检查在 Clutching 之后是否可以在越狱设备上调试该应用程序。这是使用来自 Cydia 的 BigBoss 存储库的调试服务器完成的。

注意：如果应用程序配备了反逆向工程控件，则可以检测并停止调试器。

## 查找调试符号 (MSTG-CODE-3)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#finding-debugging-symbols-mstg-code-3)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#overview_2)

作为一种好的做法，编译后的二进制文件应提供尽可能少的解释信息。附加元数据（如调试符号）的存在可能会提供有关代码的有价值信息，例如，函数名称会泄露有关函数功能的信息。执行二进制文件不需要此元数据，因此可以安全地将其丢弃以用于发布版本，这可以通过使用适当的编译器配置来完成。作为测试人员，您应该检查应用程序随附的所有二进制文件，并确保不存在任何调试符号（至少是那些揭示有关代码的任何有价值信息的符号）。

编译 iOS 应用程序时，编译器会为应用程序中的每个二进制文件（主要应用程序可执行文件、框架和应用程序扩展）生成一个调试符号列表。这些符号包括类名、全局变量以及映射到特定文件和定义它们的行号的方法和函数名。默认情况下，应用程序的调试版本将调试符号放置在已编译的二进制文件中，而应用程序的发布版本将它们放置在配套的*调试符号文件*(dSYM) 中，以减小分布式应用程序的大小。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis_2)

要验证调试符号是否存在，您可以使用[binutils](https://www.gnu.org/s/binutils/)中的 objdump或[llvm-objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html)检查所有应用程序二进制文件。

在以下代码片段中，我们在`TargetApp`（iOS 主应用程序可执行文件）上运行 objdump 以显示包含调试符号的二进制文件的典型输出，这些调试符号标有`d`(debug) 标志。查看[objdump 手册页](https://www.unix.com/man-page/osx/1/objdump/)以获取有关各种其他符号标志字符的信息。

```
$ objdump --syms TargetApp

0000000100007dc8 l    d  *UND* -[ViewController handleSubmitButton:]
000000010000809c l    d  *UND* -[ViewController touchesBegan:withEvent:]
0000000100008158 l    d  *UND* -[ViewController viewDidLoad]
...
000000010000916c l    d  *UND* _disable_gdb
00000001000091d8 l    d  *UND* _detect_injected_dylds
00000001000092a4 l    d  *UND* _isDebugged
...
```

要防止包含调试符号，`Strip Debug Symbols During Copy`请`YES`通过 XCode 项目的构建设置设置为。剥离调试符号不仅会减小二进制文件的大小，还会增加逆向工程的难度。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#dynamic-analysis_1)

动态分析不适用于查找调试符号。

## 查找调试代码和详细错误记录 (MSTG-CODE-4)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#finding-debugging-code-and-verbose-error-logging-mstg-code-4)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#overview_3)

为了加速验证并更好地理解错误，开发人员通常会包含调试代码，例如有关 API 响应以及应用程序进度和/或状态的详细日志记录语句（使用`NSLog`、`println`、`print`、`dump`和）。`debugPrint`此外，可能还有用于“管理功能”的调试代码，开发人员使用它来设置应用程序的状态或来自 API 的模拟响应。逆向工程师可以轻松地使用此信息来跟踪应用程序发生的情况。因此，应从应用程序的发布版本中删除调试代码。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis_3)

您可以对日志语句采用以下静态分析方法：

1. 将应用程序的代码导入 Xcode。
2. 搜索以下打印功能的代码：`NSLog`, `println`, `print`, `dump`, `debugPrint`。
3. 当您找到其中之一时，请确定开发人员是否在日志记录功能周围使用了包装功能，以便更好地标记要记录的语句；如果是这样，请将该功能添加到您的搜索中。
4. 对于第 2 步和第 3 步的每个结果，确定是否已设置宏或调试状态相关的守卫以在发布版本中关闭日志记录。请注意 Objective-C 如何使用预处理器宏的变化：

```
#ifdef DEBUG
    // Debug-only code
#endif
```

在 Swift 中启用此行为的过程已更改：您需要在方案中设置环境变量或在目标的构建设置中将它们设置为自定义标志。请注意，不推荐使用以下函数（这些函数可以让您确定应用程序是否是在 Swift 2.1.release-configuration 中构建的），因为 Xcode 8 和 Swift 3 不支持这些函数：

- `_isDebugAssertConfiguration`
- `_isReleaseAssertConfiguration`
- `_isFastAssertConfiguration`.

根据应用程序的设置，可能会有更多的日志记录功能。例如，当使用[CocoaLumberjack](https://github.com/CocoaLumberjack/CocoaLumberjack)时，静态分析有点不同。

对于“调试管理”代码（内置）：检查故事板以查看是否有任何流程和/或视图控制器提供的功能与应用程序应支持的功能不同。此功能可以是任何东西，从调试视图到打印的错误消息，从自定义存根响应配置到写入应用程序文件系统或远程服务器上的文件的日志。

作为开发人员，只要确保调试语句从不出现在应用程序的发布版本中，将调试语句合并到应用程序的调试版本中应该不是问题。

在 Objective-C 中，开发人员可以使用预处理器宏来过滤掉调试代码：

```
#ifdef DEBUG
    // Debug-only code
#endif
```

在 Swift 2（带有 Xcode 7）中，您必须为每个目标设置自定义编译器标志，并且编译器标志必须以“-D”开头。所以你可以在设置调试标志时使用以下注释`DMSTG-DEBUG`：

```
#if MSTG-DEBUG
    // Debug-only code
#endif
```

在 Swift 3（带有 Xcode 8）中，您可以在 Build settings/Swift compiler - Custom flags 中设置 Active Compilation Conditions。Swift 3 没有使用预处理器，而是根据定义的条件使用[条件编译块：](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/InteractingWithCAPIs.html#//apple_ref/doc/uid/TP40014216-CH8-ID34)

```
#if DEBUG_LOGGING
    // Debug-only code
#endif
```

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#dynamic-analysis_2)

动态分析应该在模拟器和设备上执行，因为开发人员有时会使用基于目标的函数（而不是基于发布/调试模式的函数）来执行调试代码。

1. 在模拟器上运行应用程序并在应用程序执行期间检查控制台中的输出。
2. 将设备连接到您的 Mac，通过 Xcode 在设备上运行应用程序，并在应用程序执行期间检查控制台中的输出。

对于其他“基于管理器”的调试代码：单击模拟器和设备上的应用程序，查看是否可以找到允许预设应用程序配置文件、允许选择实际服务器或允许来自要选择的 API 的响应。

## 检查第三方库中的弱点 (MSTG-CODE-5)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#checking-for-weaknesses-in-third-party-libraries-mstg-code-5)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#overview_4)

iOS 应用程序通常使用第三方库来加速开发，因为开发人员必须编写更少的代码才能解决问题。但是，第三方库可能包含漏洞、不兼容的许可或恶意内容。此外，组织和开发人员很难管理应用程序依赖性，包括监控库版本和应用可用的安全补丁。

目前广泛使用的包管理工具有[Swift Package Manager](https://swift.org/package-manager)、[Carthage](https://github.com/Carthage/Carthage)和[CocoaPods 三种](https://cocoapods.org/)：

- Swift 包管理器是开源的，包含在 Swift 语言中，集成到 Xcode（自 Xcode 11 起）并支持[Swift、Objective-C、Objective-C++、C 和 C++](https://developer.apple.com/documentation/swift_packages)包。它是用 Swift 编写的，去中心化的，并使用 Package.swift 文件来记录和管理项目依赖关系。
- Carthage 是开源的，可用于 Swift 和 Objective-C 包。它是用 Swift 编写的，去中心化的，并使用 Cartfile 文件来记录和管理项目依赖关系。
- CocoaPods 是开源的，可用于 Swift 和 Objective-C 包。它是用 Ruby 编写的，为公共和私有包使用集中式包注册表，并使用 Podfile 文件来记录和管理项目依赖项。

库分为两类：

- 没有（或不应）打包在实际生产应用程序中的库，例如`OHHTTPStubs`用于测试的库。
- 打包在实际生产应用程序中的库，例如`Alamofire`.

这些库可能会导致不必要的副作用：

- 一个库可能包含一个漏洞，这将使应用程序容易受到攻击。一个很好的例子是`AFNetworking`版本 2.5.1，它包含一个禁用证书验证的错误。此漏洞将允许攻击者对使用该库连接到其 API 的应用程序执行中间人攻击。
- 库无法再维护或几乎无法使用，这就是没有报告和/或修复漏洞的原因。这可能会导致通过库在您的应用程序中出现错误和/或易受攻击的代码。
- 库（Libraries）可以使用 LGPL2.1 等Licenses（许可证），这要求应用程序作者为使用该应用程序并要求深入了解其源代码的人提供对源代码的访问权限。事实上，应用程序应该被允许在修改其源代码的情况下重新分发。这可能危及应用程序的知识产权 (IP)。

请注意，此问题可能存在于多个层面：当您使用 webview 并在 webview 中运行 JavaScript 时，JavaScript 库也可能存在这些问题。这同样适用于 Cordova、React-native 和 Xamarin 应用程序的插件/库。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis_4)

#### 检测第三方库的漏洞[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#detecting-vulnerabilities-of-third-party-libraries)

为了确保应用程序使用的库没有携带漏洞，最好检查 CocoaPods 或 Carthage 安装的依赖项。

##### Swift包管理器[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#swift-package-manager)

如果使用[Swift Package Manager](https://swift.org/package-manager)管理第三方依赖，可以通过以下步骤分析第三方库的漏洞：

首先，在项目的根目录下，即 Package.swift 文件所在的位置，键入

```
swift build
```

接下来，检查文件 Package.resolved 以了解实际使用的版本，并检查给定的库是否存在已知漏洞。

您可以利用[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)的实验性[Swift Package Manager Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html)来识别所有依赖项的[通用平台枚举 (CPE)](https://nvd.nist.gov/products/cpe)命名方案以及任何相应的[通用漏洞和暴露 (CVE)](https://cve.mitre.org/)条目。使用以下命令扫描应用程序的 Package.swift 文件并生成已知易受攻击库的报告：

```
dependency-check  --enableExperimental --out . --scan Package.swift
```

##### CocoaPods[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#cocoapods)

如果使用[CocoaPods](https://cocoapods.org/)管理第三方依赖，可以通过以下步骤分析第三方库的漏洞。

首先，在项目的根目录，也就是 Podfile 所在的位置，执行以下命令：

```
sudo gem install cocoapods
pod install
```

接下来，既然已经构建了依赖关系树，您可以通过运行以下命令来创建依赖关系及其版本的概览：

```
sudo gem install cocoapods-dependencies
pod dependencies
```

上述步骤的结果现在可以用作搜索已知漏洞的不同漏洞源的输入。

> 笔记：
>
> 1. 如果开发人员使用 .podspec 文件根据自己的支持库打包所有依赖项，则可以使用实验性 CocoaPods podspec 检查器检查此 .podspec 文件。
> 2. 如果项目使用 CocoaPods 结合 Objective-C，可以使用 SourceClear。
> 3. 使用基于 HTTP 的链接而不是 HTTPS 的 CocoaPods 可能允许在下载依赖项期间进行中间人攻击，从而允许攻击者用其他内容替换（部分）库。因此，始终使用 HTTPS。

您可以利用[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)的实验性[CocoaPods Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html) 来识别所有依赖项的[通用平台枚举 (CPE)](https://nvd.nist.gov/products/cpe)命名方案以及任何相应的[通用漏洞和暴露 (CVE)](https://cve.mitre.org/)条目。使用以下命令扫描应用程序的 *.podspec 和/或 Podfile.lock 文件并生成已知易受攻击库的报告：

```
dependency-check  --enableExperimental --out . --scan Podfile.lock
```

##### Carthage[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#carthage)

如果[Carthage](https://github.com/Carthage/Carthage)用于第三方依赖，则可以通过以下步骤分析第三方库是否存在漏洞。

首先，在 Cartfile 所在的项目根目录下，键入

```
brew install carthage
carthage update --platform iOS
```

接下来，检查 Cartfile.resolved 以了解实际使用的版本，并检查给定的库是否存在已知漏洞。

> 请注意，在撰写本章时，作者还没有自动支持基于 Carthage 的依赖分析。至少，已经为 OWASP DependencyCheck 工具请求了此功能，但尚未实现（请参阅[GitHub 问题](https://github.com/jeremylong/DependencyCheck/issues/962)）。

##### 发现库漏洞[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#discovered-library-vulnerabilities)

当发现某个库包含漏洞时，则适用以下推理：

- 该库是否与应用程序打包在一起？然后查看该库是否有补丁漏洞的版本。如果不是，请检查该漏洞是否实际影响了应用程序。如果是这种情况或将来可能是这种情况，那么寻找一种提供类似功能但没有漏洞的替代方案。
- 该库是否未与应用程序打包在一起？看看有没有修复漏洞的补丁版本。如果不是这种情况，请检查该漏洞是否对构建过程有影响。该漏洞是否会阻碍构建或削弱构建管道的安全性？然后尝试寻找修复漏洞的替代方案。

如果框架作为链接库手动添加：

1. 打开 xcodeproj 文件并检查项目属性。
2. 转到选项卡**Build Phases**并检查任何库的**Link Binary With Libraries**中的条目。请参阅前面有关如何使用[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)获取类似信息的部分。

在复制粘贴源的情况下：搜索头文件（在使用 Objective-C 的情况下），否则搜索 Swift 文件以获取已知库的已知方法名称。

接下来，请注意，对于混合应用程序，您必须使用[RetireJS](https://retirejs.github.io/retire.js/)检查 JavaScript 依赖项。同样对于 Xamarin，您将必须检查 C# 依赖项。

最后，如果应用程序是高风险应用程序，您将最终手动审查库。在这种情况下，对Native代码有特定要求，这类似于 MASVS 为整个应用程序建立的要求。其次，最好检查是否应用了所有软件工程最佳实践。

#### 检测应用程序库使用的Licenses（许可证）[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#detecting-the-licenses-used-by-the-libraries-of-the-application)

为了保证不侵犯版权，最好检查Swift Packager Manager、CocoaPods或Carthage安装的依赖。

##### Swift包管理器[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#swift-package-manager_1)

当应用程序源可用并使用 Swift 包管理器时，在项目的根目录中执行以下代码，即 Package.swift 文件所在的位置：

```
swift build
```

每个依赖项的源代码现已下载到`/.build/checkouts/`项目中的文件夹中。在这里，您可以在各自的文件夹中找到每个库的Licenses（许可证）。

##### CocoaPods[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#cocoapods_1)

当应用程序源可用并使用 CocoaPods 时，执行以下步骤以获取不同的Licenses（许可证）：首先，在项目的根目录，即 Podfile 所在的位置，键入

```
sudo gem install CocoaPods
pod install
```

这将创建一个 Pods 文件夹，其中安装了所有库，每个库都在自己的文件夹中。您现在可以通过检查每个文件夹中的Licenses（许可证）文件来检查每个库的Licenses（许可证）。

##### Carthage[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#carthage_1)

当应用程序源可用并使用 Carthage 时，在 Cartfile 所在的项目根目录下执行以下代码：

```
brew install carthage
carthage update --platform iOS
```

每个依赖项的源代码现已下载到`Carthage/Checkouts`项目中的文件夹中。在这里，您可以在各自的文件夹中找到每个库的Licenses（许可证）。

##### 库（Libraries）Licenses（许可证）问题[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#issues-with-library-licenses)

当库包含应用程序 IP 需要开源的Licenses（许可证）时，检查是否有可用于提供类似功能的库的替代项。

注意：如果是混合应用程序，请检查使用的构建工具：它们中的大多数都有Licenses（许可证）枚举插件来查找正在使用的Licenses（许可证）。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#dynamic-analysis_3)

本节的动态分析包括两部分：实际Licenses（许可证）验证和检查在缺少源的情况下涉及哪些库。

需要验证Licenses（许可证）的版权是否得到遵守。这通常意味着应用程序应该有一个`about`或`EULA`部分，其中根据第三方库的许可要求注明版权声明。

#### 列出应用程序库[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#listing-application-libraries)

在执行应用程序分析时，分析应用程序依赖项（通常以库或所谓的 iOS 框架的形式）并确保它们不包含任何漏洞也很重要。即使您没有源代码，您仍然可以使用[objection](https://github.com/sensepost/objection)、[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)或 otool 等工具识别某些应用依赖项。objection是推荐的工具，因为它提供最准确的结果并且易于使用。它包含一个与 iOS Bundles 一起工作的模块，它提供了两个命令：`list_bundles`和`list_frameworks`。

该`list_bundles`命令列出了所有与框架无关的应用程序包。输出包含可执行文件名称、包 ID、库版本和库路径。

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_bundles
Executable    Bundle                                       Version  Path
------------  -----------------------------------------  ---------  -------------------------------------------
DVIA-v2       com.highaltitudehacks.DVIAswiftv2.develop          2  ...-1F0C-4DB1-8C39-04ACBFFEE7C8/DVIA-v2.app
CoreGlyphs    com.apple.CoreGlyphs                               1  ...m/Library/CoreServices/CoreGlyphs.bundle
```

该`list_frameworks`命令列出了代表框架的所有应用程序包。

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
                                                                      ...ystem/Library/Frameworks/IOKit.framework
...
```

## 测试异常处理 (MSTG-CODE-6)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#testing-exception-handling-mstg-code-6)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#overview_5)

异常通常发生在应用程序进入异常或错误状态之后。测试异常处理是为了确保应用程序将处理异常并进入安全状态，而不会通过其日志记录机制或 UI 暴露任何敏感信息。

请记住，Objective-C 中的异常处理与 Swift 中的异常处理截然不同。在同时使用遗留 Objective-C 代码和 Swift 代码编写的应用程序中桥接这两种方法可能会出现问题。

#### Objective-C 中的异常处理[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#exception-handling-in-objective-c)

Objective-C 有两种类型的错误：

**NSException** `NSException`用于处理编程和低级错误（例如，除以 0 和越界数组访问）。An`NSException`可以由`raise`引发或抛出`@throw`。除非被捕获，否则此异常将调用未处理的异常处理程序，您可以使用它记录该语句（记录将停止程序）。`@catch`如果您使用的是`@try`- -块，则允许您从异常中恢复`@catch`：

```
 @try {
    //do work here
 }

@catch (NSException *e) {
    //recover from exception
}

@finally {
    //cleanup
```

请记住，使用`NSException`带有内存管理陷阱：您需要从[finally 块](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/HandlingExceptions.html)中的 try 块中[清除分配](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/RaisingExceptions.html#//apple_ref/doc/uid/20000058-BBCCFIBF)。请注意，您可以通过在块中实例化来提升对象。`NSException``NSError``NSError``@catch`

**NSError** `NSError`用于所有其他类型的[错误](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ErrorHandling/ErrorHandling.html)。一些 Cocoa 框架 API 在它们的失败回调中提供错误作为对象，以防出现问题；那些不提供它们的`NSError`通过引用传递指向对象的指针。为方法提供`BOOL`返回类型是一种很好的做法，该方法采用指向`NSError`对象的指针来指示成功或失败。如果有返回类型，请确保返回`nil`错误。如果返回`NO`or `nil`，它允许您检查失败的错误/原因。

#### Swift 中的异常处理[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#exception-handling-in-swift)

Swift 中的异常处理 (2 - 5) 是完全不同的。try-catch 块不是用来处理`NSException`. 该块用于处理符合`Error`（Swift 3）或`ErrorType`（Swift 2）协议的错误。当 Objective-C 和 Swift 代码在应用程序中组合时，这可能具有挑战性。因此，对于用两种语言编写的程序`NSError`来说更可取。`NSException`此外，错误处理在 Objective-C 中是可选的，但`throws`必须在 Swift 中显式处理。要转换错误抛出，请查看[Apple 文档](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html)。可以抛出错误的方法使用`throws`关键字。该`Result`类型表示成功或失败，请参阅[Result](https://developer.apple.com/documentation/swift/result)，[如何在 Swift 5 中使用 Result](https://www.hackingwithswift.com/articles/161/how-to-use-result-in-swift)和[Swift 中结果类型的强大功能](https://www.swiftbysundell.com/posts/the-power-of-result-types-in-swift)。[Swift](https://developer.apple.com/library/content/documentation/Swift/Conceptual/Swift_Programming_Language/ErrorHandling.html)中有四种处理错误的方法：

- 将错误从函数传播到调用该函数的代码。在这种情况下，没有`do-catch`; 只有`throw`抛出实际错误或`try`执行抛出的方法。包含的方法`try`也需要`throws`关键字：

```
func dosomething(argumentx:TypeX) throws {
    try functionThatThrows(argumentx: argumentx)
}
```

- `do-catch`使用语句处理错误。您可以使用以下模式：

```
func doTryExample() {
    do {
        try functionThatThrows(number: 203)
    } catch NumberError.lessThanZero {
        // Handle number is less than zero
    } catch let NumberError.tooLarge(delta) {
        // Handle number is too large (with delta value)
    } catch {
        // Handle any other errors
    }
}

enum NumberError: Error {
    case lessThanZero
    case tooLarge(Int)
    case tooSmall(Int)
}

func functionThatThrows(number: Int) throws -> Bool {
    if number < 0 {
        throw NumberError.lessThanZero
    } else if number < 10 {
        throw NumberError.tooSmall(10 - number)
    } else if number > 100 {
        throw NumberError.tooLarge(100 - number)
    } else {
        return true
    }
}
```

- 将错误作为可选值处理：

```
    let x = try? functionThatThrows()
    // In this case the value of x is nil in case of an error.
```

- 使用`try!`表达式断言错误不会发生。
- 将一般错误作为`Result`返回处理：

```
enum ErrorType: Error {
    case typeOne
    case typeTwo
}

func functionWithResult(param: String?) -> Result<String, ErrorType> {
    guard let value = param else {
        return .failure(.typeOne)
    }
    return .success(value)
}

func callResultFunction() {
    let result = functionWithResult(param: "OWASP")

    switch result {
    case let .success(value):
        // Handle success
    case let .failure(error):
        // Handle failure (with error)
    }
}
```

- 使用类型处理网络和 JSON 解码错误`Result`：

```
struct MSTG: Codable {
    var root: String
    var plugins: [String]
    var structure: MSTGStructure
    var title: String
    var language: String
    var description: String
}

struct MSTGStructure: Codable {
    var readme: String
}

enum RequestError: Error {
    case requestError(Error)
    case noData
    case jsonError
}

func getMSTGInfo() {
    guard let url = URL(string: "https://raw.githubusercontent.com/OWASP/owasp-mastg/master/book.json") else {
        return
    }

    request(url: url) { result in
        switch result {
        case let .success(data):
            // Handle success with MSTG data
            let mstgTitle = data.title
            let mstgDescription = data.description
        case let .failure(error):
            // Handle failure
            switch error {
            case let .requestError(error):
                // Handle request error (with error)
            case .noData:
                // Handle no data received in response
            case .jsonError:
                // Handle error parsing JSON
            }
        }
    }
}

func request(url: URL, completion: @escaping (Result<MSTG, RequestError>) -> Void) {
    let task = URLSession.shared.dataTask(with: url) { data, _, error in
        if let error = error {
            return completion(.failure(.requestError(error)))
        } else {
            if let data = data {
                let decoder = JSONDecoder()
                guard let response = try? decoder.decode(MSTG.self, from: data) else {
                    return completion(.failure(.jsonError))
                }
                return completion(.success(response))
            }
        }
    }
    task.resume()
}
```

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis_5)

查看源代码以了解应用程序如何处理各种类型的错误（IPC 通信、远程服务调用等）。以下部分列出了在此阶段您应该为每种语言检查的内容示例。

#### Objective-C 中的静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis-in-objective-c)

确保

- 应用程序使用精心设计和统一的方案来处理异常和错误，
- Cocoa 框架异常处理正确，
- 块中分配的内存在`@try`块中释放`@finally`，
- 对于每个`@throw`，调用方法`@catch`在调用方法或`NSApplication`/`UIApplication`对象级别都有一个权限来清理敏感信息并可能恢复，
- 应用程序在处理其 UI 或日志语句中的错误时不会暴露敏感信息，并且这些语句足够冗长以向用户解释问题，
- 高风险应用程序的机密信息，例如密钥材料和身份验证信息，在`@finally`块执行期间总是被擦除，
- `raise`很少使用（当程序必须在没有进一步警告的情况下终止时使用），
- `NSError`对象不包含可能泄露敏感信息的数据。

#### Swift 中的静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis-in-swift)

确保

- 应用程序使用精心设计和统一的方案来处理错误，
- 应用程序在处理其 UI 或日志语句中的错误时不会暴露敏感信息，并且这些语句足够冗长以向用户解释问题，
- 高风险应用程序的机密信息，例如密钥材料和身份验证信息，在`defer`块执行期间总是被擦除，
- `try!`仅在预先进行适当保护的情况下使用（以编程方式验证调用的方法`try!`不会引发错误）。

#### 正确的错误处理[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#proper-error-handling)

开发人员可以通过多种方式实现正确的错误处理：

- 确保应用程序使用设计良好且统一的方案来处理错误。
- 确保按照测试用例“测试调试代码和详细错误日志记录”中的描述删除或保护所有日志记录。
- 对于用 Objective-C 编写的高风险应用程序：创建一个异常处理程序来删除不应轻易检索的秘密。处理程序可以通过`NSSetUncaughtExceptionHandler`.
- `try!`除非您确定正在调用的 throwing 方法中没有错误，否则不要在 Swift 中使用。
- 确保 Swift 错误不会传播到太多中间方法中。

### 动态测试[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#dynamic-testing)

有几种动态分析方法：

- 在 iOS 应用程序的 UI 字段中输入意外值。
- 通过提供意外或引发异常的值来测试自定义 URL 方案、粘贴板和其他应用程序间通信控件。
- 篡改网络通信和/或应用程序存储的文件。
- 对于 Objective-C，您可以使用 Cycript Hook方法并为它们提供可能导致被调用方抛出异常的参数。

在大多数情况下，应用程序不应崩溃。相反，它应该

- 从错误中恢复或进入可以通知用户无法继续的状态，
- 提供一条消息（不应该泄露敏感信息）让用户采取适当的行动，
- 从应用程序的日志机制中保留信息。

## 内存损坏错误 (MSTG-CODE-8)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#memory-corruption-bugs-mstg-code-8)

iOS 应用程序有多种方法会遇到内存损坏错误：首先是一般内存损坏错误部分中提到的Native代码问题。接下来，Objective-C 和 Swift 都有各种不安全的操作来实际包装可能会产生问题的Native代码。最后，Swift 和 Objective-C 实现都可能由于保留不再使用的对象而导致内存泄漏。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis_6)

有本地代码部分吗？如果是这样：检查一般内存损坏部分中的给定问题。本地代码在编译时更难发现。如果您有源代码，那么您可以看到 C 文件使用 .c 源文件和 .h 头文件，而 C++ 使用 .cpp 文件和 .h 文件。这与 Swift 和 Objective-C 的 .swift 和 .m 源文件略有不同。这些文件可以是源代码的一部分，也可以是第三方库的一部分，注册为框架并通过各种工具导入，例如 Carthage、Swift Package Manager 或 Cocoapods。

对于项目中的任何托管代码 (Objective-C / Swift)，请检查以下项目：

- doubleFree 问题：when`free`为给定区域调用两次而不是一次。
- 保留循环：通过将材料保存在内存中的组件之间的强引用来寻找循环依赖性。
- 使用的实例`UnsafePointer`可能会被错误地管理，这将导致各种内存损坏问题。
- 尝试`Unmanaged`手动管理对象的引用计数，导致错误的计数器编号和太晚/太快的释放。

[Realm 学院就此主题进行了精彩的演讲](https://academy.realm.io/posts/russ-bishop-unsafe-swift/)，Ray Wenderlich 就此主题提供了[一个很好的教程来了解实际发生的情况。](https://www.raywenderlich.com/780-unsafe-swift-using-pointers-and-interacting-with-c)

> 请注意，在 Swift 5 中，您只能解除分配完整的块，这意味着操场已经发生了一些变化。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#dynamic-analysis_4)

提供了各种工具来帮助识别 Xcode 中的内存错误，例如 Xcode 8 中引入的 Debug Memory graph 和 Xcode 中的 Allocations and Leaks instrument。

接下来，您可以在测试应用程序时通过在 Xcode 中启用`NSAutoreleaseFreedObjectCheckEnabled`, `NSZombieEnabled`,检查内存释放速度是否太快或太慢。`NSDebugEnabled`

有各种写得很好的解释可以帮助处理内存管理。这些可以在本章的参考列表中找到。

## 确保激活了免费的安全功能 (MSTG-CODE-9)[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#make-sure-that-free-security-features-are-activated-mstg-code-9)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#overview_6)

用于检测[二进制保护机制](https://mas.owasp.org/MASTG/General/0x04h-Testing-Code-Quality/#binary-protection-mechanisms)是否存在的测试在很大程度上取决于用于开发应用程序的语言。

尽管 Xcode 默认启用所有二进制安全功能，但对于旧应用程序验证这一点或检查编译器标志配置错误可能是相关的。以下功能适用：

- [**PIE（位置独立可执行文件）**](https://mas.owasp.org/MASTG/General/0x04h-Testing-Code-Quality/#position-independent-code)：
- PIE 适用于可执行二进制文件（Mach-O 类型`MH_EXECUTE`）。
- 但是它不适用于库（Mach-O 类型`MH_DYLIB`）。
- [**内存管理**](https://mas.owasp.org/MASTG/General/0x04h-Testing-Code-Quality/#memory-management)：
- 纯 Objective-C、Swift 和混合二进制文件都应该启用 ARC（自动引用计数）。
- 对于 C/C++ 库，开发人员负责进行适当的[手动内存管理](https://mas.owasp.org/MASTG/General/0x04h-Testing-Code-Quality/#manual-memory-management)。请参阅[“内存损坏错误 (MSTG-CODE-8)”](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#memory-corruption-bugs-mstg-code-8)。
- [**Stack Smashing Protection**](https://mas.owasp.org/MASTG/General/0x04h-Testing-Code-Quality/#stack-smashing-protection)：对于纯 Objective-C 二进制文件，应该始终启用它。由于 Swift 被设计为内存安全的，如果一个库是纯粹用 Swift 编写的，并且没有启用堆栈金丝雀，那么风险将是最小的。

学到更多：

- [OS X ABI Mach-O 文件格式参考](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
- [iOS 二进制保护](https://sensepost.com/blog/2021/on-ios-binary-protections/)
- [iOS 和 iPadOS Runtime(运行时)进程的安全性](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web)
- [Mach-O 编程主题 - 位置无关代码](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/dynamic_code.html)

检测这些保护机制是否存在的测试在很大程度上取决于用于开发应用程序的语言。例如，用于检测堆栈金丝雀存在的现有技术不适用于纯 Swift 应用程序。

#### Xcode 项目设置[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#xcode-project-settings)

##### 堆栈金丝雀保护[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#stack-canary-protection)

在 iOS 应用程序中启用堆栈金丝雀保护的步骤：

1. 在 Xcode 中，在“目标”部分选择您的目标，然后单击“构建设置”选项卡以查看目标的设置。
2. 确保在“其他 C 标志”部分中选择了“-fstack-protector-all”选项。
3. 确保启用位置独立可执行文件 (PIE) 支持。

##### PIE保护[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#pie-protection)

将 iOS 应用程序构建为 PIE 的步骤：

1. 在 Xcode 中，在“目标”部分选择您的目标，然后单击“构建设置”选项卡以查看目标的设置。
2. 将 iOS 部署目标设置为 iOS 4.3 或更高版本。
3. 确保“生成位置相关代码”（“Apple Clang - 代码生成”部分）设置为默认值（“否”）。
4. 确保“生成位置相关的可执行文件”（“链接”部分）设置为其默认值（“否”）。

##### 电弧保护[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#arc-protection)

编译器会自动为 Swift 应用程序启用 ARC `swiftc`。但是，对于 Objective-C 应用程序，您将确保通过执行以下步骤启用它：

1. 在 Xcode 中，在“目标”部分选择您的目标，然后单击“构建设置”选项卡以查看目标的设置。
2. 确保“Objective-C Automatic Reference Counting”设置为其默认值（“YES”）。

请参阅[技术问答 QA1788 构建与位置无关的可执行文件](https://developer.apple.com/library/mac/qa/qa1788/_index.html)。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#static-analysis_7)

您可以使用[otool](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#otool)来检查上述二进制安全功能。这些示例中启用了所有功能。

- 馅饼：

  ```
  $ unzip DamnVulnerableiOSApp.ipa
  $ cd Payload/DamnVulnerableIOSApp.app
  $ otool -hv DamnVulnerableIOSApp
  DamnVulnerableIOSApp (architecture armv7):
  Mach header
  magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
  MH_MAGIC ARM V7 0x00 EXECUTE 38 4292 NOUNDEFS DYLDLINK TWOLEVEL
  WEAK_DEFINES BINDS_TO_WEAK PIE
  DamnVulnerableIOSApp (architecture arm64):
  Mach header
  magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
  MH_MAGIC_64 ARM64 ALL 0x00 EXECUTE 38 4856 NOUNDEFS DYLDLINK TWOLEVEL
  WEAK_DEFINES BINDS_TO_WEAK PIE
  ```

  输出显示已设置 Mach-O 标志`PIE`。此检查适用于所有 - Objective-C、Swift 和混合应用程序，但仅适用于主要可执行文件。

- 堆栈金丝雀：

  ```
  $ otool -Iv DamnVulnerableIOSApp | grep stack
  0x0046040c 83177 ___stack_chk_fail
  0x0046100c 83521 _sigaltstack
  0x004fc010 83178 ___stack_chk_guard
  0x004fe5c8 83177 ___stack_chk_fail
  0x004fe8c8 83521 _sigaltstack
  0x00000001004b3fd8 83077 ___stack_chk_fail
  0x00000001004b4890 83414 _sigaltstack
  0x0000000100590cf0 83078 ___stack_chk_guard
  0x00000001005937f8 83077 ___stack_chk_fail
  0x0000000100593dc8 83414 _sigaltstack
  ```

  在上面的输出中，存在`__stack_chk_fail`表示正在使用堆栈金丝雀。此检查适用于纯 Objective-C 和混合应用程序，但不一定适用于纯 Swift 应用程序（即，如果它显示为已禁用则没关系，因为 Swift 在设计上是内存安全的）。

- 弧：

  ```
  $ otool -Iv DamnVulnerableIOSApp | grep release
  0x0045b7dc 83156 ___cxa_guard_release
  0x0045fd5c 83414 _objc_autorelease
  0x0045fd6c 83415 _objc_autoreleasePoolPop
  0x0045fd7c 83416 _objc_autoreleasePoolPush
  0x0045fd8c 83417 _objc_autoreleaseReturnValue
  0x0045ff0c 83441 _objc_release
  [SNIP]
  ```

  此检查适用于所有情况，包括自动启用它的纯 Swift 应用程序。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#dynamic-analysis_5)

这些检查可以使用[objection](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#objection)动态执行。这是一个例子：

```
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
--------------------  -------  -----------  -----  -----  --------  ------------  ----------
PayPal                execute  True         True   True   True      False         False
CardinalMobile        dylib    False        False  True   True      False         False
FraudForce            dylib    False        False  True   True      False         False
...
```

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#references)

- 协同设计 - https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html
- 构建您的应用程序以包含调试信息 - https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information

### 内存管理-动态分析实例[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#memory-management-dynamic-analysis-examples)

- https://developer.ibm.com/tutorials/mo-ios-memory/
- https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/MemoryMgmt.html
- https://medium.com/zendesk-engineering/ios-identifying-memory-leaks-using-the-xcode-memory-graph-debugger-e84f097b9d15

### OWASP MASVS[¶](https://mas.owasp.org/MASTG/iOS/0x06i-Testing-Code-Quality-and-Build-Settings/#owasp-masvs)

- MSTG-CODE-1：“该应用程序已签名并使用有效证书进行配置，其中的私钥受到适当保护。”
- MSTG-CODE-2：“该应用程序已在发布模式下构建，具有适用于发布构建的设置（例如不可调试）。”
- MSTG-CODE-3：“调试符号已从Native二进制文件中删除。”
- MSTG-CODE-4：“调试代码和开发人员帮助代码（例如测试代码、后门、隐藏设置）已被删除。该应用程序不会记录详细错误或调试消息。”
- MSTG-CODE-5：“移动应用程序使用的所有第三方组件，例如库和框架，都被识别并检查已知漏洞。”
- MSTG-CODE-6：“应用程序捕获并处理可能的异常。”
- MSTG-CODE-8：“在非托管代码中，安全地分配、释放和使用内存。”
- MSTG-CODE-9：“工具链提供的免费安全功能已激活，例如字节码缩小、堆栈保护、PIE 支持和自动引用计数。”
