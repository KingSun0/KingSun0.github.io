# iOS 篡改和逆向工程[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#ios-tampering-and-reverse-engineering)

## 逆向工程[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#reverse-engineering)

iOS 逆向工程是一个混合包。一方面，使用 Objective-C 和 Swift 编写的应用程序可以很好地反汇编。在 Objective-C 中，对象方法是通过称为“选择器”的动态函数指针调用的，这些指针在Runtime(运行时)按名称解析。Runtime(运行时)名称解析的优点是这些名称需要在最终二进制文件中保持完整，从而使反汇编更具可读性。不幸的是，这也意味着在反汇编程序中方法之间没有直接的交叉引用可用，并且构建流程图具有挑战性。

在本指南中，我们将介绍静态和动态分析及检测。在本章中，我们参考了[OWASP UnCrackable Apps for iOS](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#ios-crackmes)，所以如果您打算按照示例进行操作，请从 MASTG 存储库下载它们。

### 反汇编和反编译[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#disassembling-and-decompiling)

由于 Objective-C 和 Swift 根本不同，编写应用程序的编程语言会影响对其进行逆向工程的可能性。例如，Objective-C 允许在Runtime(运行时)更改方法调用。这使得连接到其他应用程序功能（[Cycript](http://www.cycript.org/)和其他逆向工程工具大量使用的技术）变得容易。这种“方法调配”在 Swift 中的实现方式不同，这种差异使得该技术在 Swift 中比在 Objective-C 中更难执行。

在 iOS 上，所有应用程序代码（包括 Swift 和 Objective-C）都被编译为机器代码（例如 ARM）。因此，要分析 iOS 应用程序，需要反汇编程序。

如果要从 App Store 反汇编应用程序，请先删除 Fairplay DRM。“iOS 基本安全测试”一章中的“[获取应用程序二进制文件”部分解释了如何操作。](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#acquiring-the-app-binary)

在本节中，术语“app binary”是指包含编译代码的应用程序包中的 Macho-O 文件，不应与应用程序包 - IPA 文件混淆。有关 IPA 文件组成的更多详细信息，请参阅“基本 iOS 安全测试”一章中[的“探索应用程序包”部分。](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#exploring-the-app-package)

#### 使用 IDA Pro 反汇编[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#disassembling-with-ida-pro)

如果你有 IDA Pro 的Licenses（许可证），你也可以使用 IDA Pro 分析应用程序二进制文件。

> 不幸的是，IDA 的免费版本不支持 ARM 处理器类型。

要开始，只需在 IDA Pro 中打开应用程序二进制文件。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/ida_macho_import.png)

打开文件后，IDA Pro 将执行自动分析，这可能需要一段时间，具体取决于二进制文件的大小。自动分析完成后，您可以在**IDA View** (Disassembly) 窗口中浏览反汇编，并在**Functions**窗口中探索函数，两者都显示在下面的屏幕截图中。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/ida_main_window.png)

默认情况下，常规 IDA Pro Licenses（许可证）不包含反编译器，并且需要额外的 Hex-Rays 反编译器Licenses（许可证），这很昂贵。相比之下，Ghidra 带有一个非常强大的免费内置反编译器，使其成为逆向工程的一个引人注目的替代方案。

如果您有常规的 IDA Pro Licenses（许可证）并且不想购买 Hex-Rays 反编译器，您可以通过安装IDA Pro的[GhIDA 插件来使用 Ghidra 的反编译器。](https://github.com/Cisco-Talos/GhIDA/)

本章的大部分内容适用于用 Objective-C 编写或具有桥接类型的应用程序，这些类型与 Swift 和 Objective-C 兼容。大多数与 Objective-C 配合良好的工具的 Swift 兼容性正在得到改进。例如，Frida 支持[Swift 绑定](https://github.com/frida/frida-swift)。

## 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#static-analysis)

静态分析 iOS 应用程序的首选方法涉及使用原始 Xcode 项目文件。理想情况下，您将能够编译和调试应用程序以快速识别源代码的任何潜在问题。

在无法访问原始源代码的情况下对 iOS 应用程序进行黑盒分析需要进行逆向工程。例如，没有适用于 iOS 应用程序的反编译器（尽管大多数商业和开源反汇编器可以提供二进制文件的伪源代码视图），因此深度检查需要您阅读汇编代码。

### 基本信息收集[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#basic-information-gathering)

在本节中，我们将了解一些使用静态分析收集有关给定应用程序基本信息的方法和工具。

#### 应用二进制[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#application-binary)

您可以使用[类转储](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#class-dump)来获取有关应用程序源代码中方法的信息。下面的示例使用[Damn Vulnerable iOS App](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#dvia-v2)来演示这一点。我们的二进制文件是所谓的胖二进制文件，这意味着它可以在 32 位和 64 位平台上执行：

解压缩应用程序并运行[otool](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#otool)：

```
unzip DamnVulnerableiOSApp.ipa
cd Payload/DamnVulnerableIOSApp.app
otool -hv DamnVulnerableIOSApp
```

输出将如下所示：

```
DamnVulnerableIOSApp (architecture armv7):
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
   MH_MAGIC      ARM         V7  0x00     EXECUTE    33       3684   NOUNDEFS DYLDLINK TWOLEVEL PIE
DamnVulnerableIOSApp (architecture arm64):
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64        ALL  0x00     EXECUTE    33       4192   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

请注意架构：`armv7`（32 位）和`arm64`（64 位）。这种胖二进制文件的设计允许将应用程序部署在不同的体系结构上。要使用类转储分析应用程序，我们必须创建一个所谓的瘦二进制文件，它只包含一个架构：

```
lipo -thin armv7 DamnVulnerableIOSApp -output DVIA32
```

然后我们可以继续执行类转储：

```
iOS8-jailbreak:~ root# class-dump DVIA32

@interface FlurryUtil : ./DVIA/DVIA/DamnVulnerableIOSApp/DamnVulnerableIOSApp/YapDatabase/Extensions/Views/Internal/
{
}
+ (BOOL)appIsCracked;
+ (BOOL)deviceIsJailbroken;
```

注意加号，这意味着这是一个返回 BOOL 类型的类方法。减号表示这是一个实例方法。请参阅后面的部分以了解它们之间的实际区别。

> 一些商业反汇编程序（例如[Hopper](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#hopper-commercial-tool)）会自动执行这些步骤，您将能够看到反汇编的二进制文件和类信息。

以下命令列出共享库：

```
otool -L <binary>
```

#### 检索字符串[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#retrieving-strings)

在分析二进制文件时，字符串始终是一个很好的起点，因为它们为相关代码提供上下文。例如，诸如“Cryptogram generation failed”之类的错误日志字符串向我们暗示相邻代码可能负责生成密码。

为了从 iOS 二进制文件中提取字符串，您可以使用 Ghidra 或 Cutter 等 GUI 工具，或者依赖基于 CLI 的工具，例如*字符串*Unix 实用程序 ( `strings <path_to_binary>`) 或 radare2 的 rabin2 ( `rabin2 -zz <path_to_binary>`)。使用基于 CLI 的工具时，您可以利用 grep 等其他工具（例如结合正则表达式）进一步过滤和分析结果。

#### 交叉引用[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#cross-references)

Ghidra 可用于分析 iOS 二进制文件并通过右键单击所需函数并选择**Show References to 来**获取交叉引用。

#### 接口使用[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#api-usage)

iOS 平台为应用程序中的常用功能提供了许多内置库，例如加密、蓝牙、NFC、网络和位置库。确定这些库在应用程序中的存在可以为我们提供有关其底层工作的有价值的信息。

例如，如果应用程序正在导入该`CC_SHA256`函数，则表明该应用程序将使用 SHA256 算法执行某种哈希运算。有关如何分析 iOS 加密 API 的更多信息，请参阅“ [iOS 加密 API](https://mas.owasp.org/MASTG/iOS/0x06e-Testing-Cryptography/) ”部分。

同样，上述方法可用于确定应用程序在何处以及如何使用蓝牙。例如，使用蓝牙通道执行通信的应用程序必须使用核心蓝牙框架中的函数，例如`CBCentralManager`或`connect`。使用[iOS 蓝牙文档](https://developer.apple.com/documentation/corebluetooth)，您可以确定关键函数并围绕这些函数导入开始分析。

#### 网络通讯[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#network-communication)

您可能遇到的大多数应用程序都连接到远程端点。即使在您执行任何动态分析（例如流量捕获和分析）之前，您也可以通过枚举应用程序应该与之通信的域来获得一些初始输入或入口点。

通常，这些域将作为字符串出现在应用程序的二进制文件中。可以通过检索字符串（如上所述）或使用 Ghidra 等工具检查字符串来提取域。后一种选择有一个明显的优势：它可以为您提供上下文，因为您将能够通过检查交叉引用来查看每个域在哪个上下文中使用。

从这里开始，您可以使用此信息来获得更多见解，这些见解可能会在稍后的分析过程中使用，例如，您可以将域与固定证书进行匹配，或者对域名执行进一步的侦察以了解有关目标环境的更多信息。

安全连接的实施和验证可能是一个复杂的过程，需要考虑许多方面。例如，许多应用程序使用除 HTTP 之外的其他协议，例如 XMPP 或纯 TCP 数据包，或执行证书固定以试图阻止 MITM 攻击。

请记住，在大多数情况下，仅使用静态分析是不够的，与动态替代方案相比甚至可能效率极低，动态替代方案将获得更可靠的结果（例如使用拦截代理）。在本节中，我们只触及了表面，因此请参阅“iOS 基本安全测试”一章中的“[基本网络监控/嗅探”部分，并查看“ ](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#basic-network-monitoringsniffing)[iOS 网络通信](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/)”一章中的测试用例以获取更多信息.

### 手动（反向）代码审查[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#manual-reversed-code-review)

#### 查看反汇编的 Objective-C 和 Swift 代码[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#reviewing-disassembled-objective-c-and-swift-code)

在本节中，我们将手动探索 iOS 应用程序的二进制代码并对其执行静态分析。手动分析可能是一个缓慢的过程，需要极大的耐心。良好的人工分析可以使动态分析更加成功。

执行静态分析没有硬性规定，但很少有经验法则可用于系统地进行手动分析：

- 了解正在评估的应用程序的工作 - 应用程序的目标以及在输入错误的情况下它的行为方式。
- 探索应用程序二进制文件中存在的各种字符串，这可能非常有帮助，例如在应用程序中发现有趣的功能和可能的错误处理逻辑。
- 寻找名称与我们的目标相关的函数和类。
- 最后，找到应用程序的各个入口点，然后从那里继续探索应用程序。

> 无论用于分析的工具如何，本节中讨论的技术都是通用的和适用的。

##### Objective-C[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#objective-c)

除了在“[反汇编和反编译](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#disassembling-and-decompiling)”部分中学到的技术外，对于本部分，您还需要对[Objective-C Runtime(运行时)](https://developer.apple.com/documentation/objectivec/objective-c_runtime)有一些了解。例如，像`_objc_msgSend`或这样的函数`_objc_release`对于 Objective-C Runtime(运行时)特别有意义。

我们将使用[UnCrackable App for iOS Level 1](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#ios-uncrackable-l1)，它的简单目标是找到隐藏在二进制文件中某处的*秘密字符串。*该应用程序只有一个主屏幕，用户可以通过在提供的文本字段中输入自定义字符串进行交互。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_app_home_screen2.png)

当用户输入错误的字符串时，应用程序会显示一个带有“验证失败”消息的弹出窗口。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_app_wrong_input.png)

您可以记下弹出窗口中显示的字符串，因为这在搜索处理输入和做出决定的代码时可能会有所帮助。幸运的是，这个应用程序的复杂性和交互很简单，这预示着我们的逆向努力。

> 对于本节中的静态分析，我们将使用 Ghidra 9.0.4。Ghidra 9.1_beta 自动分析有一个错误，不显示 Objective-C 类。

我们可以通过在 Ghidra 中打开它来检查二进制文件中存在的字符串。列出的字符串一开始可能让人不知所措，但是通过一些逆向 Objective-C 代码的经验，您将学习如何*过滤*和丢弃没有真正帮助或相关的字符串。例如，下面屏幕截图中显示的是为 Objective-C Runtime(运行时)生成的。其他字符串在某些情况下可能会有帮助，例如那些包含符号（函数名称、类名称等）的字符串，我们将在执行静态分析时使用它们来检查是否正在使用某些特定函数。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_ghidra_objc_runtime_strings.png)

如果我们继续仔细分析，我们可以发现字符串“Verification Failed”，它用于在输入错误时弹出窗口。如果您遵循此字符串的交叉引用 (Xref)，您将到达该类`buttonClick`的函数`ViewController`。我们将`buttonClick`在本节后面研究该功能。当进一步检查应用程序中的其他字符串时，只有少数看起来可能是*隐藏标志*的候选者。您也可以尝试并验证它们。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_ghidra_strings.png)

展望未来，我们有两条路可走。我们可以开始分析`buttonClick`上述步骤中确定的功能，或者从各个入口点开始分析应用程序。在现实世界的情况下，大多数时候你会选择第一种路径，但从学习的角度来看，在本节中我们将选择后一种路径。

iOS 应用程序根据其在[应用程序生命周期](https://developer.apple.com/documentation/uikit/app_and_environment/managing_your_app_s_life_cycle)中的状态调用 iOS Runtime(运行时)提供的不同预定义函数。这些功能被称为应用程序的入口点。例如：

- `[AppDelegate application:didFinishLaunchingWithOptions:]`当应用程序第一次启动时被调用。
- `[AppDelegate applicationDidBecomeActive:]`当应用程序从非活动状态移动到活动状态时调用。

许多应用程序在这些部分中执行关键代码，因此它们通常是系统地遵循代码的良好起点。

一旦我们完成了对`AppDelegate`类中所有函数的分析，我们可以得出结论，不存在相关代码。上述函数中缺少任何代码引发了一个问题——从哪里调用应用程序的初始化代码？

幸运的是，当前应用程序的代码库很小，我们可以在**Symbol Tree**视图中找到另一个`ViewController`类。在这个类中，function函数看起来很有趣。如果查看 的文档，您会发现它还可以用于对视图执行额外的初始化。`viewDidLoad`[`viewDidLoad`](https://developer.apple.com/documentation/uikit/uiviewcontroller/1621495-viewdidload)

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_ghidra_viewdidload_decompile.png)

如果我们检查这个函数的反编译，就会发现一些有趣的事情。例如，在第 31 行调用了一个本地函数，并`setHidden`在第 27-29 行将一个标记设置为 1 来初始化标签。您可以记下这些观察结果并继续探索此类中的其他功能。为简洁起见，探索该功能的其他部分留给读者作为练习。

在我们的第一步中，我们观察到应用程序仅在按下 UI 按钮时才验证输入字符串。因此，分析`buttonClick`功能是一个明显的目标。如前所述，此函数还包含我们在弹出窗口中看到的字符串。在第 29 行，正在根据（第 23 行`isEqualString`保存的输出）的结果做出决定。`uVar1`用于比较的输入来自文本输入字段（来自用户）和`label`. 因此，我们可以假设隐藏标志存储在该标签中。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_ghidra_buttonclick_decompiled.png)

现在我们已经了解了完整的流程并获得了有关申请流程的所有信息。我们还得出结论，隐藏标志存在于文本标签中，为了确定标签的值，我们需要重新访问`viewDidLoad`函数，并了解所识别的Native函数中发生了什么。Native函数的分析在“[审查反汇编的Native代码](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#reviewing-disassembled-native-code)”中讨论。

#### 查看反汇编的Native代码[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#reviewing-disassembled-native-code)

分析反汇编的Native代码需要很好地理解底层平台使用的调用约定和指令。在本节中，我们将研究原生代码的 ARM64 反汇编。Azeria Labs Tutorials[的 ARM Assembly Basics Introduction to ARM Assembly Basics](https://azeria-labs.com/writing-arm-assembly-part-1/)是了解 ARM 体系结构的一个很好的起点。这是我们将在本节中使用的内容的快速摘要：

- 在 ARM64 中，寄存器的大小为 64 位，称为 Xn，其中 n 是从 0 到 31 的数字。如果使用寄存器的低 (LSB) 32 位，则称为 Wn。
- 函数的输入参数在 X0-X7 寄存器中传递。
- 函数的返回值通过 X0 寄存器传递。
- 加载 (LDR) 和存储 (STR) 指令用于从寄存器读取或写入内存。
- B、BL、BLX是用于调用函数的分支指令。

同样如上所述，Objective-C 代码也被编译为原生二进制代码，但分析 C/C++ 原生代码可能更具挑战性。在 Objective-C 的情况下，存在各种符号（尤其是函数名称），这简化了代码的理解。在上面的部分中，我们了解到像`setText`,这样的函数名称的存在`isEqualStrings`可以帮助我们快速理解代码的语义。如果是 C/C++ Native代码，如果所有二进制文件都被剥离，则可能会出现很少或没有符号来帮助我们对其进行分析。

反编译器可以帮助我们分析本地代码，但应谨慎使用。现代反编译器非常复杂，在它们用来反编译代码的许多技术中，有一些是基于启发式的。基于启发式的技术可能并不总能给出正确的结果，其中一种情况是确定给定Native函数的输入参数的数量。拥有分析反汇编代码的知识，在反编译器的协助下，可以使分析Native代码更不容易出错。

我们将分析`viewDidLoad`上一节中在函数中标识的Native函数。该函数位于偏移量 0x1000080d4 处。此函数的返回值用于`setText`标签的函数调用。此文本用于与用户输入进行比较。因此，我们可以确定这个函数将返回一个字符串或等价物。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_ghidra_native_disassembly.png)

我们在函数的反汇编中首先看到的是函数没有输入。在整个函数中不会读取寄存器 X0-X7。此外，还有对其他函数的多次调用，例如 0x100008158、0x10000dbf0 等处的函数。

对应于一个这样的函数调用的指令可以在下面看到。分支指令`bl`用于调用0x100008158处的函数。

```
1000080f0 1a 00 00 94     bl         FUN_100008158
1000080f4 60 02 00 39     strb       w0,[x19]=>DAT_10000dbf0
```

函数的返回值（在 W0 中找到）存储到寄存器 X19 中的地址（`strb`将一个字节存储到寄存器中的地址）。我们可以看到其他函数调用的模式相同，返回值存储在 X19 寄存器中，每次偏移量都比上一次函数调用多 1。此行为可能与一次填充字符串数组的每个索引相关联。每个返回值都被写入该字符串数组的索引中。有 11 次这样的调用，根据目前的证据，我们可以明智地猜测隐藏标志的长度是 11。在反汇编结束时，函数返回这个字符串数组的地址。

```
100008148 e0 03 13 aa     mov        x0=>DAT_10000dbf0,x19
```

为了确定隐藏标志的值，我们需要知道上面标识的每个后续函数调用的返回值。在分析函数 0x100006fb4 时，我们可以观察到这个函数比我们分析的前一个函数更大更复杂。函数图在分析复杂函数时非常有用，因为它有助于更好地理解函数的控制流。通过单击子菜单中的**显示函数图**图标，可以在 Ghidra 中获取函数图。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_ghidra_function_graph.png)

完全手动分析所有Native函数将非常耗时，而且可能不是最明智的方法。在这种情况下，强烈建议使用动态分析方法。例如，通过使用Hook或简单地调试应用程序等技术，我们可以轻松确定返回值。通常，使用动态分析方法然后回退到手动分析反馈循环中的函数是个好主意。这样您就可以同时受益于这两种方法，同时节省时间和减少工作量。动态分析技术在“[动态分析](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#dynamic-analysis)”部分讨论。

### 自动静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#automated-static-analysis)

有几种用于分析 iOS 应用程序的自动化工具可用；其中大部分是商业工具。免费开源工具[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)和[objection](https://github.com/sensepost/objection)具有一些静态和动态分析功能。[“测试工具”](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/)一章的“静态源代码分析”部分列出了其他工具。

不要回避使用自动扫描仪进行分析——它们可以帮助您摘取容易获得的成果，并让您专注于更有趣的分析方面，例如业务逻辑。请记住，静态分析器可能会产生误报和漏报；始终仔细审查调查结果。

## 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#dynamic-analysis)

越狱设备让生活变得轻松：您不仅可以轻松获得对设备的特权访问权限，而且由于没有代码签名，您可以使用更强大的动态分析技术。在 iOS 上，大多数动态分析工具都基于 Cydia Substrate（一种用于开发Runtime(运行时)补丁的框架）或 Frida（一种动态内省工具）。对于基本的 API 监控，您可以在不知道 Substrate 或 Frida 工作原理的所有细节的情况下逃脱——您可以简单地使用现有的 API 监控工具。

### 非越狱设备动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#dynamic-analysis-on-non-jailbroken-devices)

如果您无法访问越狱设备，您可以修补并重新打包目标应用程序以在启动时加载动态库（例如[Frida 小工具](https://www.frida.re/docs/gadget/)以使用 Frida 和相关工具（如对象）启用动态测试）。通过这种方式，您可以检测应用程序并执行动态分析所需的所有操作（当然，您不能通过这种方式突破沙盒）。但是，此技术仅在应用程序二进制文件未经过 FairPlay 加密（即从 App Store 获取）时才有效。

#### 自动重新包装[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#automated-repackaging)

[Objection](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#objection)使应用程序重新打包的过程自动化。您可以在官方[wiki 页面](https://github.com/sensepost/objection/wiki)上找到详尽的文档。

对于大多数用例，使用 objection 的重新打包功能就足够了。然而，在一些复杂的场景中，您可能需要更细粒度的控制或更可定制的重新打包过程。[如果是这样的话，你可以在“手动重新](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#manual-repackaging)打包”中阅读重新打包和重新打包过程的详细解释。

#### 手动重新打包[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#manual-repackaging)

由于 Apple 令人困惑的供应和代码签名系统，重新签署应用程序比您预期的更具挑战性。iOS 不会运行应用程序，除非您获得完全正确的配置文件和代码签名标头。这需要学习很多概念——证书类型、Bundle ID、应用程序 ID、团队标识符，以及 Apple 的构建工具如何将它们连接起来。让操作系统运行不是通过默认方法 (Xcode) 构建的二进制文件可能是一个艰巨的过程。

我们将使用[optool](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#optool)、Apple 的构建工具和一些 shell 命令。我们的方法受到[Vincent Tan 的 Swizzler 项目的](https://github.com/vtky/Swizzler2/)启发。[NCC 小组](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/)描述了一种替代的重新打包方法。

要重现下面列出的步骤，请从 OWASP 移动测试指南存储库下载[UnCrackable iOS App Level 1 。](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#ios-uncrackable-l1)我们的目标是在启动期间加载 UnCrackable 应用程序`FridaGadget.dylib`，以便我们可以使用 Frida 检测该应用程序。

> 请注意，以下步骤仅适用于 macOS，因为 Xcode 仅适用于 macOS。

#### 获取开发人员配置文件和证书[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#getting-a-developer-provisioning-profile-and-certificate)

*配置文件*是由 Apple 签名的plist 文件，它将您的代码签名证书添加到一台或多台设备上的已接受证书列表中。换句话说，这代表 Apple 出于某些原因明确允许您的应用程序运行，例如在选定的设备上进行调试（开发配置文件）。配置文件还包括授予您的应用程序的*权利。*该*证书*包含您将用于签名的私钥。

根据您是否注册为 iOS 开发人员，您可以通过以下方式之一获取证书和配置文件：

**使用 iOS 开发者帐户：**

如果您之前使用 Xcode 开发和部署过 iOS 应用程序，那么您已经安装了自己的代码签名证书。使用[`security`](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#security)命令（仅限 macOS）列出您的签名身份：

```
$ security find-identity -v
 1) 61FA3547E0AF42A11E233F6A2B255E6B6AF262CE "iPhone Distribution: Company Name Ltd."
 2) 8004380F331DCA22CC1B47FB1A805890AE41C938 "iPhone Developer: Bernhard Müller (RV852WND79)"
```

登录 Apple Developer 门户发布新的 App ID，然后发布并下载配置文件。App ID 是由两部分组成的字符串：Apple 提供的团队 ID 和可以设置为任意值的捆绑包 ID 搜索字符串，例如`com.example.myapp`. 请注意，您可以使用单个应用程序 ID 重新签署多个应用程序。确保您创建的是*开发*配置文件而不是*分发*配置文件，以便您可以调试应用程序。

在下面的示例中，我使用我的签名身份，它与我公司的开发团队相关联。我为这些示例创建了 App ID“sg.vp.repackaged”和配置文件“AwesomeRepackaging”。我最终得到了文件`AwesomeRepackaging.mobileprovision`——在下面的 shell 命令中用你自己的文件名替换它。

**使用普通 Apple ID：**

即使您不是付费开发人员，Apple 也会发布免费的开发配置文件。您可以通过 Xcode 和您的常规 Apple 帐户获取配置文件：只需创建一个空的 iOS 项目并`embedded.mobileprovision`从应用程序容器中提取，该容器位于您的主目录的 Xcode 子目录中：`~/Library/Developer/Xcode/DerivedData/<ProjectName>/Build/Products/Debug-iphoneos/<ProjectName>.app/`. [NCC 博客文章“无需越狱的 iOS 检测”](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/)非常详细地解释了这个过程。

获得供应配置文件后，您可以使用[`security`](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#security)命令检查其内容。您会在配置文件中找到授予应用程序的权利，以及允许的证书和设备。您将需要这些来进行代码签名，因此将它们提取到一个单独的 plist 文件中，如下所示。查看文件内容以确保一切都符合预期。

```
$ security cms -D -i AwesomeRepackaging.mobileprovision > profile.plist
$ /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist
$ cat entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>application-identifier</key>
 <string>LRUD9L355Y.sg.vantagepoint.repackage</string>
 <key>com.apple.developer.team-identifier</key>
 <string>LRUD9L355Y</string>
 <key>get-task-allow</key>
 <true/>
 <key>keychain-access-groups</key>
 <array>
   <string>LRUD9L355Y.*</string>
 </array>
</dict>
</plist>
```

请注意应用程序标识符，它是团队 ID (LRUD9L355Y) 和 Bundle ID (sg.vantagepoint.repackage) 的组合。此配置文件仅对具有此 App ID 的应用程序有效。`get-task-allow`密钥也很重要：当设置为 时，`true`允许其他进程（例如调试服务器）附加到应用程序（因此，这将`false`在分发配置文件中设置为）。

### 基本信息收集[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#basic-information-gathering_1)

在 iOS 上，收集有关正在运行的进程或应用程序的基本信息可能比 Android 更具挑战性。在 Android（或任何基于 Linux 的操作系统）上，进程信息通过*procfs*公开为可读文本文件。因此，通过解析这些文本文件，可以在获得 root 权限的设备上获取有关目标进程的任何信息。相反，在 iOS 上不存在等效的 procfs。此外，在 iOS 上，删除了许多用于探索进程信息的标准 UNIX 命令行工具，例如 lsof 和 vmmap，以减小固件大小。

在本节中，我们将学习如何使用 lsof 等命令行工具在 iOS 上收集进程信息。由于这些工具中有许多默认情况下不存在于 iOS 上，因此我们需要通过其他方法安装它们。例如，可以使用[Cydia](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#cydia)安装 lsof （可执行文件不是可用的最新版本，但仍然满足我们的目的）。

#### 打开文件[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#open-files)

`lsof`是一个功能强大的命令，并提供有关正在运行的进程的大量信息。它可以提供所有打开文件的列表，包括流、网络文件或常规文件。当不带任何选项调用该`lsof`命令时，它将列出属于系统上所有活动进程的所有打开文件，而当使用标志`-c <process name>`or调用时`-p <pid>`，它将返回指定进程的打开文件列表。[手册页](http://man7.org/linux/man-pages/man8/lsof.8.html)详细显示了各种其他选项。

用于使用`lsof`PID 2828 运行的 iOS 应用程序，列出各种打开的文件，如下所示。

```
iPhone:~ root# lsof -p 2828
COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME
iOweApp 2828 mobile  cwd    DIR    1,2      864      2 /
iOweApp 2828 mobile  txt    REG    1,3   206144 189774 /private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp
iOweApp 2828 mobile  txt    REG    1,3     5492 213230 /private/var/mobile/Containers/Data/Application/5AB3E437-9E2D-4F04-BD2B-972F6055699E/tmp/com.apple.dyld/iOweApp-6346DC276FE6865055F1194368EC73CC72E4C5224537F7F23DF19314CF6FD8AA.closure
iOweApp 2828 mobile  txt    REG    1,3    30628 212198 /private/var/preferences/Logging/.plist-cache.vqXhr1EE
iOweApp 2828 mobile  txt    REG    1,2    50080 234433 /usr/lib/libobjc-trampolines.dylib
iOweApp 2828 mobile  txt    REG    1,2   344204  74185 /System/Library/Fonts/AppFonts/ChalkboardSE.ttc
iOweApp 2828 mobile  txt    REG    1,2   664848 234595 /usr/lib/dyld
...
```

#### 加载Native库(NATIVE LIBRARIES)[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#loaded-native-libraries)

您可以使用`list_frameworks`命令 in [objection](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#objection)列出所有代表框架的应用程序包。

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
                                                                      ...ystem/Library/Frameworks/IOKit.framework
...

#### Open Connections

`lsof` command when invoked with option `-i`, it gives the list of open network ports for all active processes on the device. To get a list of open network ports for a specific process, the `lsof -i -a -p <pid>` command can be used, where `-a` (AND) option is used for filtering. Below a filtered output for PID 1 is shown.

```bash
iPhone:~ root# lsof -i -a -p 1
COMMAND PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd   1 root   27u  IPv6 0x69c2ce210efdc023      0t0  TCP *:ssh (LISTEN)
launchd   1 root   28u  IPv6 0x69c2ce210efdc023      0t0  TCP *:ssh (LISTEN)
launchd   1 root   29u  IPv4 0x69c2ce210eeaef53      0t0  TCP *:ssh (LISTEN)
launchd   1 root   30u  IPv4 0x69c2ce210eeaef53      0t0  TCP *:ssh (LISTEN)
launchd   1 root   31u  IPv4 0x69c2ce211253b90b      0t0  TCP 192.168.1.12:ssh->192.168.1.8:62684 (ESTABLISHED)
launchd   1 root   42u  IPv4 0x69c2ce211253b90b      0t0  TCP 192.168.1.12:ssh->192.168.1.8:62684 (ESTABLISHED)
```

#### 沙箱检查[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#sandbox-inspection)

在 iOS 上，每个应用程序都有一个沙盒文件夹来存储其数据。根据 iOS 安全模型，一个应用程序的沙盒文件夹不能被另一个应用程序访问。此外，用户无法直接访问 iOS 文件系统，因此无法浏览或从文件系统中提取数据。在 iOS < 8.3 中，有可用于浏览设备文件系统的应用程序，例如 iExplorer 和 iFunBox，但在最新版本的 iOS (>8.3) 中，沙盒规则更加严格，这些应用程序不再工作。因此，如果您需要访问文件系统，则只能在越狱设备上访问它。作为越狱过程的一部分，应用程序沙盒保护被禁用，因此可以轻松访问沙盒文件夹。

应用程序沙盒文件夹的内容已经在iOS 基本安全测试一章的“[访问应用程序数据目录”中讨论过。](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#accessing-app-data-directories)本章概述了文件夹结构以及您应该分析的目录。

### 调试[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#debugging)

如果您有 Linux 背景，您会期望`ptrace`系统调用像您习惯的那样强大，但出于某种原因，Apple 决定让它不完整。LLDB 等 iOS 调试器使用它来附加、步进或继续该过程，但它们不能使用它来读取或写入内存（所有`PT_READ_*`和`PT_WRITE*`请求都丢失）。相反，他们必须获得一个所谓的 Mach 任务端口（通过`task_for_pid`使用目标进程 ID 调用），然后使用 Mach IPC 接口 API 函数来执行诸如挂起目标进程和读/写寄存器状态（`thread_get_state`/ `thread_set_state`）和虚拟内存 ( `mach_vm_read`/ `mach_vm_write`)。

> 有关详细信息，您可以参考 GitHub 中的 LLVM 项目，其中包含[LLDB 的源代码](https://github.com/llvm/llvm-project/tree/main/lldb)以及“Mac OS X 和 iOS 内部结构：Apple 的核心”[#levin] 中的第 5 章和第 13 章以及第 4 章“跟踪和调试”来自“Mac 黑客手册”[#miller]。

#### 使用 LLDB 进行调试[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#debugging-with-lldb)

Xcode 安装的默认 debugserver 可执行文件不能用于附加到任意进程（它通常仅用于调试使用 Xcode 部署的自开发应用程序）。要启用第三方应用程序的调试，`task_for_pid-allow`必须将授权添加到 debugserver 可执行文件，以便调试器进程可以调用`task_for_pid`以获取目标 Mach 任务端口，如前所示。一种简单的方法是将授权添加到[Xcode 附带的 debugserver 二进制文件](http://iphonedevwiki.net/index.php/Debugserver)。

要获取可执行文件，请挂载以下 DMG 映像：

```
/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/<target-iOS-version>/DeveloperDiskImage.dmg
```

您将`/usr/bin/`在已安装卷的目录中找到 debugserver 可执行文件。将其复制到一个临时目录，然后创建一个名为`entitlements.plist`以下内容的文件：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.springboard.debugapplications</key>
    <true/>
    <key>run-unsigned-code</key>
    <true/>
    <key>get-task-allow</key>
    <true/>
    <key>task_for_pid-allow</key>
    <true/>
</dict>
</plist>
```

使用代码设计应用权利：

```
codesign -s - --entitlements entitlements.plist -f debugserver
```

将修改后的二进制文件复制到测试设备上的任意目录。以下示例使用 usbmuxd 通过 USB 转发本地端口。

```
iproxy 2222 22
scp -P 2222 debugserver root@localhost:/tmp/
```

注意：在 iOS 12 及更高版本上，使用以下过程对从 XCode 映像获取的 debugserver 二进制文件进行签名。

\1) 通过 scp 将 debugserver 二进制文件复制到设备，例如 /tmp 文件夹中。

\2) 通过 SSH 连接到设备并创建名为 entitlements.xml 的文件，内容如下：

````
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>platform-application</key>
    <true/>
    <key>com.apple.private.security.no-container</key>
    <true/>
    <key>com.apple.private.skip-library-validation</key>
    <true/>
    <key>com.apple.backboardd.debugapplications</key>
    <true/>
    <key>com.apple.backboardd.launchapplications</key>
    <true/>
    <key>com.apple.diagnosticd.diagnostic</key>
    <true/>
    <key>com.apple.frontboard.debugapplications</key>
    <true/>
    <key>com.apple.frontboard.launchapplications</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.network.server</key>
    <true/>
    <key>com.apple.springboard.debugapplications</key>
    <true/>
    <key>com.apple.system-task-ports</key>
    <true/>
    <key>get-task-allow</key>
    <true/>
    <key>run-unsigned-code</key>
    <true/>
    <key>task_for_pid-allow</key>
    <true/>
</dict>
</plist>
```
````

\3) 键入以下命令对 debugserver 二进制文件进行签名：

````
```bash
ldid -Sentitlements.xml debugserver
```
````

\4) 验证是否可以通过以下命令执行 debugserver 二进制文件：

````
```bash
./debugserver
```
````

您现在可以将 debugserver 附加到设备上运行的任何进程。

```
VP-iPhone-18:/tmp root# ./debugserver *:1234 -a 2670
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-320.2.89
for armv7.
Attaching to process 2670...
```

使用以下命令，您可以通过在目标设备上运行的调试服务器启动应用程序：

```
debugserver -x backboard *:1234 /Applications/MobileSMS.app/MobileSMS
```

附加到已经运行的应用程序：

```
debugserver *:1234 -a "MobileSMS"
```

您现在可以从主机连接到 iOS 设备：

```
(lldb) process connect connect://<ip-of-ios-device>:1234
```

键入`image list`会给出主要可执行文件和所有依赖库的列表。

#### 调试发布应用[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#debugging-release-apps)

在上一节中，我们了解了如何使用 LLDB 在 iOS 设备上设置调试环境。在本节中，我们将使用此信息并学习如何调试第 3 方发布的应用程序。我们将继续使用[iOS Level 1 的 UnCrackable App，](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#ios-uncrackable-l1)并使用调试器解决它。

与调试构建相比，为发布构建编译的代码经过优化以实现最佳性能和最小二进制构建大小。作为一般的最佳实践，大多数调试符号都被删除以用于发布版本，从而在逆向工程和调试二进制文件时增加了一层复杂性。

由于缺少调试符号，回溯输出中缺少符号名称，并且无法通过简单地使用函数名称来设置断点。幸运的是，调试器还支持直接在内存地址上设置断点。在本节的后面，我们将学习如何这样做并最终解决 crackme 挑战。

在使用内存地址设置断点之前需要做一些基础工作。它需要确定两个偏移量：

1. 断点偏移量：我们要设置断点的代码的*地址偏移量。*该地址是通过在 Ghidra 等反汇编程序中对代码执行静态分析获得的。
2. ASLR 偏移量：当前进程的*ASLR 偏移量。*由于 ASLR 偏移量是在应用程序的每个新实例上随机生成的，因此必须为每个调试会话单独获取。这是使用调试器本身确定的。

> iOS 是一种现代操作系统，采用多种技术来减轻代码执行攻击，其中一种技术是地址空间随机化布局 (ASLR)。在应用程序的每次新执行中，都会生成一个随机的 ASLR 移位偏移量，并且各种进程的数据结构会按此偏移量移位。

调试器中要使用的最终断点地址是上述两个地址的总和（断点偏移量 + ASLR 移位偏移量）。这种方法假设反汇编程序和 iOS 使用的图像基地址（稍后讨论）是相同的，大多数情况下都是如此。

当在 Ghidra 等反汇编程序中打开二进制文件时，它会通过模拟相应操作系统的加载程序来加载二进制文件。加载二进制文件的地址称为*图像基地址*。该二进制文件中的所有代码和符号都可以使用与该图像基地址的常量地址偏移量来寻址。在Ghidra中，可以通过确定Mach-O文件的起始地址来获取图像基地址。在这种情况下，它是 0x100000000。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/debugging_ghidra_image_base_address.png)

根据我们之前在“[手动（反向）代码审查”部分对](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#manual-reversed-code-review)[UnCrackable Level 1 应用程序](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#ios-uncrackable-l1)的分析，隐藏字符串的值存储在设置了标志的标签中。在反汇编中，此标签的文本值存储在寄存器中，通过from存储在偏移量 0x100004520 处。这是我们的*断点偏移量*。`hidden``X21``mov``X0`

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/debugging_ghidra_breakpoint.png)

对于第二个地址，我们需要确定给定进程的*ASLR 偏移量。*可以使用 LLDB 命令确定 ASLR 偏移量`image list -o -f`。输出显示在下面的屏幕截图中。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/debugging_lldb_image_list.png)

在输出中，第一列包含图像的序列号 ([X])，第二列包含随机生成的 ASLR 偏移量，而第三列包含图像的完整路径，最后，括号中的内容显示将 ASLR 偏移量添加到原始图像基地址后的图像基地址 (0x100000000 + 0x70000 = 0x100070000)。您会注意到 0x100000000 的图像基地址与 Ghidra 中的相同。现在，要获得代码位置的有效内存地址，我们只需要将 ASLR 偏移量添加到 Ghidra 中标识的地址即可。设置断点的有效地址将为 0x100004520 + 0x70000 = 0x100074520。可以使用命令设置断点`b 0x100074520`。

> 在上面的输出中，您可能还会注意到许多作为图像列出的路径并未指向 iOS 设备上的文件系统。相反，它们指向运行 LLDB 的主机上的某个位置。这些图像是系统库，在主机上提供调试符号以帮助应用程序开发和调试（作为 Xcode iOS SDK 的一部分）。因此，您可以直接使用函数名为这些库设置断点。

放置断点并运行应用程序后，一旦遇到断点，就会停止执行。现在您可以访问和探索流程的当前状态。在这种情况下，您从前面的静态分析中知道寄存器`X0`包含隐藏字符串，因此让我们探索一下。在 LLDB 中，您可以使用`po`( *print object* ) 命令打印 Objective-C 对象。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/debugging_lldb_breakpoint_solution.png)

瞧，借助静态分析和调试器可以轻松解决 crackme。LLDB 中实现了许多功能，包括更改寄存器的值、更改进程内存中的值，甚至[使用 Python 脚本自动执行任务](https://lldb.llvm.org/use/python.html)。

Apple 官方推荐使用 LLDB 进行调试，但 GDB 也可以在 iOS 上使用。上面讨论的技术也适用于使用 GDB 进行调试，前提是将 LLDB 特定命令[更改为 GDB 命令](https://lldb.llvm.org/use/map.html)。

### 追踪[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#tracing)

跟踪涉及记录有关程序执行的信息。与 Android 相比，可用于跟踪 iOS 应用程序各个方面的选项有限。在本节中，我们将严重依赖 Frida 等工具来执行跟踪。

#### 方法追踪[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#method-tracing)

拦截 Objective-C 方法是一种有用的 iOS 安全测试技术。例如，您可能对数据存储操作或网络请求感兴趣。在下面的示例中，我们将编写一个简单的跟踪器来记录通过 iOS 标准 HTTP API 发出的 HTTP(S) 请求。我们还将向您展示如何将跟踪器注入 Safari 网络浏览器。

在以下示例中，我们假设您正在使用越狱设备。如果不是这种情况，您首先需要按照重新打包[和重新签名](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#repackaging-and-re-signing)部分中概述的步骤重新打包 Safari 应用程序。

Frida 附带了`frida-trace`一个函数跟踪工具。通过标志`frida-trace`接受 Objective-C 方法。`-m`您可以将通配符传递给它 well-given `-[NSURL *]`，例如，将自动在所有类选择器`frida-trace`上安装Hook。`NSURL`我们将使用它来大致了解当用户打开 URL 时 Safari 调用哪些库函数。

在设备上运行 Safari 并确保设备已通过 USB 连接。然后开始`frida-trace`如下：

```
$ frida-trace -U -m "-[NSURL *]" Safari
Instrumenting functions...
-[NSURL isMusicStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isMusicStoreURL_.js"
-[NSURL isAppStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isAppStoreURL_.js"
(...)
Started tracing 248 functions. Press Ctrl+C to stop.
```

接下来，导航到 Safari 中的新网站。`frida-trace`您应该在控制台上看到跟踪的函数调用。请注意，`initWithURL:`调用该方法是为了初始化一个新的 URL 请求对象。

```
           /* TID 0xc07 */
  20313 ms  -[NSURLRequest _initWithCFURLRequest:0x1043bca30 ]
 20313 ms  -[NSURLRequest URL]
(...)
 21324 ms  -[NSURLRequest initWithURL:0x106388b00 ]
 21324 ms     | -[NSURLRequest initWithURL:0x106388b00 cachePolicy:0x0 timeoutInterval:0x106388b80
```

#### Native库(NATIVE LIBRARIES)跟踪[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#native-libraries-tracing)

如本章前面所述，iOS 应用程序还可以包含Native代码（C/C++ 代码），也可以使用`frida-trace`CLI 对其进行跟踪。例如，您可以`open`通过运行以下命令来跟踪对该函数的调用：

```
frida-trace -U -i "open" sg.vp.UnCrackable1
```

使用 Frida 跟踪Native代码的总体方法和进一步改进与 Android“[跟踪](https://mas.owasp.org/MASTG/Android/0x05c-Reverse-Engineering-and-Tampering/#tracing)”部分中讨论的方法类似。

不幸的是，没有诸如`strace`或`ftrace`可用于跟踪 iOS 应用程序的系统调用或函数调用的工具。Only `DTrace`Exists，这是一个非常强大且用途广泛的跟踪工具，但它仅适用于 MacOS，不适用于 iOS。

### 基于仿真的分析[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#emulation-based-analysis)

#### iOS模拟器[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#ios-simulator)

Apple 在 Xcode 中提供了一个模拟器应用程序，它为 iPhone、iPad 或 Apple Watch 提供了一个*真实的 iOS 设备外观*用户界面。它允许您在开发过程中快速原型化和测试应用程序的调试版本，但实际上**它不是模拟器**。[之前在“基于仿真的动态分析](https://mas.owasp.org/MASTG/General/0x04c-Tampering-and-Reverse-Engineering/#emulation-based-dynamic-analysis)”部分讨论了模拟器和仿真器之间的区别。

在开发和调试应用程序时，Xcode 工具链生成 x86 代码，可以在 iOS 模拟器中执行。但是，对于发布版本，仅生成 ARM 代码（与 iOS 模拟器不兼容）。这就是为什么从 Apple App Store 下载的应用程序不能用于 iOS 模拟器上的任何类型的应用程序分析。

#### Corellium[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#corellium)

Corellium 是一种商业工具，它提供运行实际 iOS 固件的虚拟 iOS 设备，是有史以来唯一公开可用的 iOS 模拟器。由于它是专有产品，因此关于实现的信息不多。Corellium 没有可用的社区Licenses（许可证），因此我们不会详细介绍它的使用。

Corellium 允许您启动一个设备（越狱与否）的多个实例，这些实例可以作为本地设备访问（使用简单的 VPN 配置）。它能够拍摄和恢复设备状态的快照，还为设备提供了一个方便的基于 Web 的Shell。最后也是最重要的是，由于其“模拟器”特性，您可以执行从 Apple App Store 下载的应用程序，从而实现您从真实 iOS（越狱）设备上了解到的任何类型的应用程序分析。

请注意，为了在 Corellium 设备上安装 IPA，它必须未加密并使用有效的 Apple 开发人员证书签名。[在此处](https://support.corellium.com/en/articles/6181345-testing-third-party-ios-apps)查看更多信息。

## 二进制分析[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#binary-analysis)

Android的“[动态分析](https://mas.owasp.org/MASTG/Android/0x05c-Reverse-Engineering-and-Tampering/#dynamic-analysis)”部分已经讨论了使用二进制分析框架进行二进制分析的介绍。我们建议您重新访问此部分并刷新有关此主题的概念。

对于 Android，我们使用 Angr 的符号执行引擎来解决一个挑战。在本节中，我们将首先使用 Unicorn 解决[UnCrackable App for iOS Level 1](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#ios-uncrackable-l1)挑战，然后我们将重新访问 Angr 二进制分析框架来分析挑战，但我们将使用其具体执行（或动态执行）功能而不是符号执行.

### 独角兽[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#unicorn)

[Unicorn](https://www.unicorn-engine.org/)是一个基于[QEMU](https://www.qemu.org/)的轻量级、多架构 CPU 仿真器框架，并通过添加专为 CPU 仿真而设计的有用功能[超越了它。](https://www.unicorn-engine.org/docs/beyond_qemu.html)Unicorn 提供了执行处理器指令所需的基本基础设施。在本节中，我们将使用[Unicorn 的 Python 绑定](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python)解决[UnCrackable App for iOS Level 1](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#ios-uncrackable-l1)挑战。

要使用 Unicorn 的*全部功能*，我们需要实现所有必要的基础设施，这些基础设施通常可以从操作系统中轻松获得，例如二进制加载器、链接器和其他依赖项，或者使用另一个更高级别的框架，例如利用 Unicorn 模拟 CPU 指令的[Qiling](https://qiling.io/)，但了解操作系统上下文。然而，这对于这个非常本地化的挑战来说是多余的，因为只执行二进制文件的一小部分就足够了。

在“[查看反汇编Native代码](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#reviewing-disassembled-native-code)”部分进行手动分析时，我们确定地址 0x1000080d4 处的函数负责动态生成秘密字符串。正如我们即将看到的，所有必要的代码几乎都包含在二进制文件中，这使得这是使用像 Unicorn 这样的 CPU 模拟器的完美场景。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/manual_reversing_ghidra_native_disassembly.png)

如果我们分析该函数和后续函数调用，我们将观察到不存在对任何外部库的硬依赖，也没有执行任何系统调用。函数外部的唯一访问发生在地址 0x1000080f4，其中值存储到地址 0x10000dbf0，映射到该`__data`部分。

因此，为了正确模拟这部分代码，除了`__text`section（包含指令）之外，我们还需要加载`__data`section。

为了使用 Unicorn 解决挑战，我们将执行以下步骤：

- 通过运行获取 ARM64 版本的二进制文件`lipo -thin arm64 <app_binary> -output uncrackable.arm64`（也可以使用 ARMv7）。
- 从二进制文件中提取`__text`和部分。`__data`
- 创建并映射要用作堆栈内存的内存。
- 创建内存并加载`__text`and`__data`部分。
- 通过提供起始地址和结束地址来执行二进制文件。
- 最后，转储函数的返回值，在本例中是我们的秘密字符串。

为了从 Mach-O 二进制文件中提取内容`__text`和部分，我们将使用[LIEF](https://lief.quarkslab.com/)，它提供了一种方便的抽象来操作多种可执行文件格式。在将这些部分加载到内存之前，我们需要确定它们的基址，例如使用 Ghidra、Radare2 或 IDA Pro。`__data`

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/uncrackable_sections.png)

从上表中，我们将使用基地址 0x10000432c`__text`和 0x10000d3e8`__data`将它们加载到内存中。

> 为 Unicorn 分配内存时，内存地址应为 4k 页对齐，并且分配的大小应为 1024 的倍数。

以下脚本模拟 0x1000080d4 处的函数并转储秘密字符串：

```
import lief
from unicorn import *
from unicorn.arm64_const import *

# --- Extract __text and __data section content from the binary ---
binary = lief.parse("uncrackable.arm64")
text_section = binary.get_section("__text")
text_content = text_section.content

data_section = binary.get_section("__data")
data_content = data_section.content

# --- Setup Unicorn for ARM64 execution ---
arch = "arm64le"
emu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# --- Create Stack memory ---
addr = 0x40000000
size = 1024*1024
emu.mem_map(addr, size)
emu.reg_write(UC_ARM64_REG_SP, addr + size - 1)

# --- Load text section --
base_addr = 0x100000000
tmp_len = 1024*1024
text_section_load_addr = 0x10000432c
emu.mem_map(base_addr, tmp_len)
emu.mem_write(text_section_load_addr, bytes(text_content))

# --- Load data section ---
data_section_load_addr = 0x10000d3e8
emu.mem_write(data_section_load_addr, bytes(data_content))

# --- Hack for stack_chk_guard ---
# without this will throw invalid memory read at 0x0
emu.mem_map(0x0, 1024)
emu.mem_write(0x0, b"00")


# --- Execute from 0x1000080d4 to 0x100008154 ---
emu.emu_start(0x1000080d4, 0x100008154)
ret_value = emu.reg_read(UC_ARM64_REG_X0)

# --- Dump return value ---
print(emu.mem_read(ret_value, 11))
```

> 您可能会注意到在地址 0x0 处有一个额外的内存分配，这是一个简单的 hack around`stack_chk_guard`检查。没有这个，就会出现无效的内存读取错误，无法执行二进制文件。通过这个 hack，程序将访问 0x0 处的值并将其用于`stack_chk_guard`检查。

总而言之，使用 Unicorn 确实需要在执行二进制文件之前进行一些额外的设置，但是一旦完成，此工具可以帮助深入了解二进制文件。它提供了执行完整二进制文件或其中有限部分的灵活性。Unicorn 还公开了 API 以将Hook附加到执行中。使用这些钩子，您可以在执行期间的任何时刻观察程序的状态，甚至可以操纵寄存器或变量值，并强制探索程序中的其他执行分支。在 Unicorn 中运行二进制文件的另一个优点是您无需担心各种检查，例如 root/越狱检测或调试器检测等。

### Angr[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#angr)

[Angr](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#angr)是一个非常通用的工具，提供多种技术来促进二进制分析，同时支持各种文件格式和硬件指令集。

> Angr 中的 Mach-O 后端没有得到很好的支持，但它非常适合我们的案例。

在手动分析“[查看反汇编Native代码](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#reviewing-disassembled-native-code)”部分中的代码时，我们发现执行进一步的手动分析很麻烦。偏移处的函数`0x1000080d4`被确定为包含秘密字符串的最终目标。

如果我们重新访问该函数，我们可以看到它涉及多个子函数调用，有趣的是，这些函数都不依赖于其他库调用或系统调用。这是使用 Angr 的具体执行引擎的完美案例。请按照以下步骤解决此挑战：

- 通过运行获取 ARM64 版本的二进制文件`lipo -thin arm64 <app_binary> -output uncrackable.arm64`（也可以使用 ARMv7）。
- `Project`通过加载上述二进制文件创建一个 Angr 。
- `callable`通过传递要执行的函数的地址来获取一个对象。来自 Angr 文档：“Callable 是二进制文件中函数的表示，可以像Native python 函数一样与之交互。”。
- 将上述`callable`对象传递给具体的执行引擎，在本例中为`claripy.backends.concrete`.
- 访问内存，从上述函数返回的指针中提取字符串。

```
import angr
import claripy

def solve():

    # Load the binary by creating angr project.
    project = angr.Project('uncrackable.arm64')

    # Pass the address of the function to the callable
    func = project.factory.callable(0x1000080d4)

    # Get the return value of the function
    ptr_secret_string = claripy.backends.concrete.convert(func()).value
    print("Address of the pointer to the secret string: " + hex(ptr_secret_string))

    # Extract the value from the pointer to the secret string
    secret_string = func.result_state.mem[ptr_secret_string].string.concrete
    print(f"Secret String: {secret_string}")

solve()
```

上面，Angr 在其具体执行引擎之一提供的执行环境中执行了 ARM64 代码。结果是从内存中访问的，就好像程序是在真实设备上执行的一样。这个案例是一个很好的例子，二进制分析框架使我们能够对二进制文件进行全面分析，即使在没有运行它所需的专用设备的情况下也是如此。

## 篡改和Runtime(运行时)检测[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#tampering-and-runtime-instrumentation)

### 修补、重新打包和重新签名[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#patching-repackaging-and-re-signing)

是时候认真起来了！如您所知，IPA 文件实际上是 ZIP 存档，因此您可以使用任何 ZIP 工具来解压缩存档。

```
unzip UnCrackable-Level1.ipa
```

#### 修补示例：安装 Frida Gadget[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#patching-example-installing-frida-gadget)

如果你想在非越狱设备上使用 Frida，你需要将`FridaGadget.dylib`. 先下载：

```
curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
```

复制`FridaGadget.dylib`到应用程序目录并使用[optool](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#optool)将加载命令添加到“UnCrackable Level 1”二进制文件。

```
$ unzip UnCrackable-Level1.ipa
$ cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/
$ optool install -c load -p "@executable_path/FridaGadget.dylib"  -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
```

#### 修补示例：使应用程序可调试[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#patching-example-making-an-app-debuggable)

默认情况下，Apple App Store 上提供的应用程序不可调试。为了调试 iOS 应用程序，它必须`get-task-allow`启用授权。此授权允许其他进程（如调试器）附加到应用程序。Xcode 没有`get-task-allow`在分发配置文件中添加授权；它仅被列入白名单并添加到开发配置文件中。

`get-task-allow`因此，要调试从 App Store 获取的 iOS 应用程序，需要使用具有授权的开发配置文件对其进行重新签名。下一节将讨论如何重新签署应用程序。

#### 重新打包和重新签名[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#repackaging-and-re-signing)

当然，篡改应用程序会使主要可执行文件的代码签名无效，因此它不会在未越狱的设备上运行。您需要替换供应配置文件，并使用配置文件`FridaGadget.dylib`中列出的证书对主要可执行文件和您制作的包含文件（例如 ）进行签名。

首先，让我们将自己的配置文件添加到包中：

```
cp AwesomeRepackaging.mobileprovision Payload/UnCrackable\ Level\ 1.app/embedded.mobileprovision
```

接下来，我们需要确保中的 Bundle ID与配置文件中指定的 Bundle ID 匹配，因为协同设计工具将在签名期间`Info.plist`从中读取 Bundle ID ；`Info.plist`错误的值将导致无效的签名。

```
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier sg.vantagepoint.repackage" Payload/UnCrackable\ Level\ 1.app/Info.plist
```

最后，我们使用协同设计工具对两个二进制文件重新签名。您需要使用*自己的*签名身份（本例中为 8004380F331DCA22CC1B47FB1A805890AE41C938），您可以通过执行命令输出`security find-identity -v`。

```
$ rm -rf Payload/UnCrackable\ Level\ 1.app/_CodeSignature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938  Payload/UnCrackable\ Level\ 1.app/FridaGadget.dylib
Payload/UnCrackable Level 1.app/FridaGadget.dylib: replacing existing signature
```

`entitlements.plist`是您为空的 iOS 项目创建的文件。

```
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 --entitlements entitlements.plist Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Payload/UnCrackable Level 1.app/UnCrackable Level 1: replacing existing signature
```

现在您应该准备好运行修改后的应用程序。[使用ios-deploy](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#ios-deploy)在设备上部署和运行应用程序：

```
ios-deploy --debug --bundle Payload/UnCrackable\ Level\ 1.app/
```

如果一切顺利，应用程序应该以调试模式启动并附加 LLDB。然后 Frida 也应该能够附加到该应用程序。您可以通过 frida-ps 命令验证这一点：

```
$ frida-ps -U
PID  Name
---  ------
499  Gadget
```

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/fridaStockiOS.png)

当出现问题时（通常会这样），供应配置文件和代码签名标头之间的不匹配是最可能的原因。阅读[官方文档](https://developer.apple.com/support/code-signing/)有助于您了解代码签名过程。Apple 的[权利故障排除页面](https://developer.apple.com/library/content/technotes/tn2415/_index.html)也是一个有用的资源。

#### 修补 React Native 应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#patching-react-native-applications)

如果已经使用[React Native](https://facebook.github.io/react-native)框架开发，主要的应用代码在文件`Payload/[APP].app/main.jsbundle`. 此文件包含 JavaScript 代码。大多数情况下，此文件中的 JavaScript 代码会被缩小。使用工具[JStillery](https://mindedsecurity.github.io/jstillery)，可以重试文件的人类可读版本，这将允许代码分析。[JStillery](https://github.com/mindedsecurity/jstillery/)的CLI 版本和本地服务器比在线版本更可取，因为后者会将源代码公开给第三方。

安装时，应用程序存档从 iOS 10 开始解压到文件夹`/private/var/containers/Bundle/Application/[GUID]/[APP].app`中，因此可以在此位置修改主要的 JavaScript 应用程序文件。

要确定应用程序文件夹的确切位置，您可以使用工具[ipainstaller](https://cydia.saurik.com/package/com.slugrail.ipainstaller/)：

1. 使用该命令`ipainstaller -l`列出设备上安装的应用程序。从输出列表中获取目标应用程序的名称。
2. 使用该命令`ipainstaller -i [APP_NAME]`显示有关目标应用程序的信息，包括安装和数据文件夹位置。
3. 采用以 开头的行中引用的路径`Application:`。

使用以下方法修补 JavaScript 文件：

1. 导航到应用程序文件夹。
2. 将文件内容复制`Payload/[APP].app/main.jsbundle`到一个临时文件中。
3. 用于`JStillery`美化和去混淆临时文件的内容。
4. 识别临时文件中应修补的代码并对其进行修补。
5. 将*修补后的代码*放在一行中并将其复制到原始`Payload/[APP].app/main.jsbundle`文件中。
6. 关闭并重新启动应用程序。

### 动态仪表[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#dynamic-instrumentation)

#### 信息收集[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#information-gathering)

在本节中，我们将学习如何使用 Frida 获取有关正在运行的应用程序的信息。

#### 获取加载的类及其方法[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#getting-loaded-classes-and-their-methods)

在 Frida REPL Objective-C Runtime(运行时)中，该`ObjC`命令可用于访问正在运行的应用程序中的信息。在`ObjC`命令中，该函数`enumerateLoadedClasses`列出了给定应用程序的加载类。

```
$ frida -U -f com.iOweApp

[iPhone::com.iOweApp]-> ObjC.enumerateLoadedClasses()
{
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": [
        "__NSBlockVariable__",
        "__NSGlobalBlock__",
        "__NSFinalizingBlock__",
        "__NSAutoBlock__",
        "__NSMallocBlock__",
        "__NSStackBlock__"
    ],
    "/private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp": [
        "JailbreakDetection",
        "CriticalLogic",
        "ViewController",
        "AppDelegate"
    ]
}
```

使用`ObjC.classes.<classname>.$ownMethods`在每个类中声明的方法都可以列出。

```
[iPhone::com.iOweApp]-> ObjC.classes.JailbreakDetection.$ownMethods
[
    "+ isJailbroken"
]

[iPhone::com.iOweApp]-> ObjC.classes.CriticalLogic.$ownMethods
[
    "+ doSha256:",
    "- a:",
    "- AES128Operation:data:key:iv:",
    "- coreLogic",
    "- bat",
    "- b:",
    "- hexString:"
]
```

#### 获取加载的库[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#getting-loaded-libraries)

在Frida REPL中可以使用`Process`命令获取进程相关信息。在`Process`命令中，该函数`enumerateModules`列出了加载到进程内存中的库。

```
[iPhone::com.iOweApp]-> Process.enumerateModules()
[
    {
        "base": "0x10008c000",
        "name": "iOweApp",
        "path": "/private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp",
        "size": 49152
    },
    {
        "base": "0x1a1c82000",
        "name": "Foundation",
        "path": "/System/Library/Frameworks/Foundation.framework/Foundation",
        "size": 2859008
    },
    {
        "base": "0x1a16f4000",
        "name": "libobjc.A.dylib",
        "path": "/usr/lib/libobjc.A.dylib",
        "size": 200704
    },

    ...
```

同理可以得到各种线程的相关信息。

```
Process.enumerateThreads()
[
    {
        "context": {
            ...
       },
        "id": 1287,
        "state": "waiting"
    },

    ...
```

该`Process`命令公开了可以根据需要探索的多个功能。一些有用的函数是`findModuleByAddress`，除此之外。`findModuleByName``enumerateRanges`

#### 方法Hook[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#method-hooking)

##### Frida[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#frida)

在[“执行跟踪”](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#execution-tracing)一节中，我们在 Safari 中导航到网站时使用了 frida-trace，发现该`initWithURL:`方法被调用以初始化新的 URL 请求对象。[我们可以在苹果开发者网站](https://developer.apple.com/documentation/foundation/nsbundle/1409352-initwithurl?language=objc)上查看这个方法的声明：

```
- (instancetype)initWithURL:(NSURL *)url;
```

使用此信息，我们可以编写一个 Frida 脚本来拦截该`initWithURL:`方法并打印传递给该方法的 URL。完整的脚本如下。请务必阅读代码和内联注释以了解发生了什么。

```
import sys
import frida


# JavaScript to be injected
frida_code = """

    // Obtain a reference to the initWithURL: method of the NSURLRequest class
    var URL = ObjC.classes.NSURLRequest["- initWithURL:"];

    // Intercept the method
    Interceptor.attach(URL.implementation, {
        onEnter: function(args) {
            // Get a handle on NSString
            var NSString = ObjC.classes.NSString;

            // Obtain a reference to the NSLog function, and use it to print the URL value
            // args[2] refers to the first method argument (NSURL *url)
            var NSLog = new NativeFunction(Module.findExportByName('Foundation', 'NSLog'), 'void', ['pointer', '...']);

            // We should always initialize an autorelease pool before interacting with Objective-C APIs
            var pool = ObjC.classes.NSAutoreleasePool.alloc().init();

            try {
                // Creates a JS binding given a NativePointer.
                var myNSURL = new ObjC.Object(args[2]);

                // Create an immutable ObjC string object from a JS string object.
                var str_url = NSString.stringWithString_(myNSURL.toString());

                // Call the iOS NSLog function to print the URL to the iOS device logs
                NSLog(str_url);

                // Use Frida's console.log to print the URL to your terminal
                console.log(str_url);

            } finally {
                pool.release();
            }
        }
    });
"""

process = frida.get_usb_device().attach("Safari")
script = process.create_script(frida_code)
script.load()

sys.stdin.read()
```

在 iOS 设备上启动 Safari。在连接的主机上运行上述 Python 脚本并打开设备日志（如“iOS 基本安全测试”一章的“监控系统日志”部分所述）。尝试在 Safari 中打开一个新的 URL，例如https://github.com/OWASP/owasp-mastg；您应该会在日志和终端中看到 Frida 的输出。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06c/frida-xcode-log.png)

当然，这个例子只是说明了你可以用 Frida 做的事情之一。要释放该工具的全部潜力，您应该学习使用它的[JavaScript API](https://www.frida.re/docs/javascript-api/)。Frida 网站的文档部分提供了在 iOS 上使用 Frida 的[教程](https://www.frida.re/docs/ios/)和[示例](https://www.frida.re/docs/examples/ios/)。

#### 过程探索[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#process-exploration)

在测试应用程序时，进程探索可以让测试人员深入了解应用程序进程内存。它可以通过Runtime(运行时)检测来实现，并允许执行以下任务：

- 检索内存映射和加载的库。
- 搜索特定数据的出现。
- 经过查找，得到内存映射中某个偏移量的位置。
- 执行内存转储并*离线*检查或反向工程二进制数据。
- 在Runtime(运行时)对二进制文件或框架进行逆向工程。

如您所见，这些任务相当支持和/或被动，它们将帮助我们收集支持其他技术的数据和信息。因此，它们通常与方法Hook等其他技术结合使用。

在以下部分中，您将使用[r2frida](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#r2frida)直接从应用程序Runtime(运行时)检索信息。首先打开一个 r2frida 会话到目标应用程序（例如[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)），它应该在你的 iPhone 上运行（通过 USB 连接）。使用以下命令：

```
r2 frida://usb//iGoat-Swift
```

##### 内存映射和检查[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#memory-maps-and-inspection)

您可以通过运行以下命令检索应用程序的内存映射`\dm`：

```
[0x00000000]> \dm
0x0000000100b7c000 - 0x0000000100de0000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
0x0000000100de0000 - 0x0000000100e68000 rw- /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
0x0000000100e68000 - 0x0000000100e97000 r-- /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
...
0x0000000100ea8000 - 0x0000000100eb0000 rw-
0x0000000100eb0000 - 0x0000000100eb4000 r--
0x0000000100eb4000 - 0x0000000100eb8000 r-x /usr/lib/TweakInject.dylib
0x0000000100eb8000 - 0x0000000100ebc000 rw- /usr/lib/TweakInject.dylib
0x0000000100ebc000 - 0x0000000100ec0000 r-- /usr/lib/TweakInject.dylib
0x0000000100f60000 - 0x00000001012dc000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/Frameworks/Realm.framework/Realm
```

在搜索或探索应用程序内存时，您始终可以验证当前偏移量在内存映射中的位置。您无需注意并搜索此列表中的内存地址，只需运行`\dm.`. 您将在下一节“内存中搜索”中找到示例。

如果您只对应用加载的模块（二进制文件和库）感兴趣，可以使用以下命令`\il`列出所有模块：

```
[0x00000000]> \il
0x0000000100b7c000 iGoat-Swift
0x0000000100eb4000 TweakInject.dylib
0x00000001862c0000 SystemConfiguration
0x00000001847c0000 libc++.1.dylib
0x0000000185ed9000 Foundation
0x000000018483c000 libobjc.A.dylib
0x00000001847be000 libSystem.B.dylib
0x0000000185b77000 CFNetwork
0x0000000187d64000 CoreData
0x00000001854b4000 CoreFoundation
0x00000001861d3000 Security
0x000000018ea1d000 UIKit
0x0000000100f60000 Realm
```

如您所料，您可以将库的地址与内存映射相关联：例如，主应用程序二进制文件[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)位于 ，`0x0000000100b7c000`而 Realm Framework 位于`0x0000000100f60000`。

您也可以使用objection来显示相同的信息。

```
$ objection --gadget OWASP.iGoat-Swift explore

OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # memory list modules
Save the output by adding `--json modules.json` to this command

Name                              Base         Size                  Path
--------------------------------  -----------  --------------------  ------------------------------------------------------------------------------
iGoat-Swift                       0x100b7c000  2506752 (2.4 MiB)     /var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGo...
TweakInject.dylib                 0x100eb4000  16384 (16.0 KiB)      /usr/lib/TweakInject.dylib
SystemConfiguration               0x1862c0000  446464 (436.0 KiB)    /System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguratio...
libc++.1.dylib                    0x1847c0000  368640 (360.0 KiB)    /usr/lib/libc++.1.dylib
```

##### 内存搜索[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#in-memory-search)

内存中搜索是一种非常有用的技术，可用于测试应用程序内存中可能存在的敏感数据。

请参阅 r2frida 的搜索命令帮助 ( `\/?`) 以了解搜索命令并获取选项列表。以下仅显示其中的一个子集：

```
[0x00000000]> \/?
 /      search
 /j     search json
 /w     search wide
 /wj    search wide json
 /x     search hex
 /xj    search hex json
...
```

您可以使用搜索设置调整搜索`\e~search`。例如，`\e search.quiet=true;`将只打印结果并隐藏搜索进度：

```
[0x00000000]> \e~search
e search.in=perm:r--
e search.quiet=false
```

现在，我们将继续使用默认值并专注于字符串搜索。在第一个示例中，您可以从搜索您知道应该位于应用程序主二进制文件中的内容开始：

```
[0x00000000]> \/ iGoat
Searching 5 bytes: 69 47 6f 61 74
Searching 5 bytes in [0x0000000100b7c000-0x0000000100de0000]
...
hits: 509
0x100d7d332 hit2_0 iGoat_Swift24StringAnalysisExerciseVCC
0x100d7d3b2 hit2_1 iGoat_Swift28BrokenCryptographyExerciseVCC
0x100d7d442 hit2_2 iGoat_Swift23BackgroundingExerciseVCC
0x100d7d4b2 hit2_3 iGoat_Swift9AboutCellC
0x100d7d522 hit2_4 iGoat_Swift12FadeAnimatorV
```

现在开始第一个命中，寻找它并检查你在内存映射中的当前位置：

```
[0x00000000]> s 0x100d7d332
[0x100d7d332]> \dm.
0x0000000100b7c000 - 0x0000000100de0000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
```

正如预期的那样，您位于主[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)二进制文件的区域（接收、读取和执行）。在上一节中，您看到主二进制文件位于`0x0000000100b7c000`和之间`0x0000000100e97000`。

现在，对于第二个示例，您可以搜索既不在应用程序二进制文件中也不在任何加载的库中的内容，通常是用户输入。打开[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)应用程序并在菜单中导航到**Authentication** -> **Remote Authentication** -> **Start**。在那里您会找到一个可以覆盖的密码字段。写入字符串“owasp-mstg”，但暂时不要单击“**登录**” 。执行以下两个步骤。

```
[0x00000000]> \/ owasp-mstg
hits: 1
0x1c06619c0 hit3_0 owasp-mstg
```

事实上，该字符串可以在 address 处找到`0x1c06619c0`。寻找`s`到那里并检索当前内存区域`\dm.`。

```
[0x100d7d332]> s 0x1c06619c0
[0x1c06619c0]> \dm.
0x00000001c0000000 - 0x00000001c8000000 rw-
```

现在您知道该字符串位于内存映射的 rw-（读写）区域。

此外，您可以搜索出现的[宽版本字符串](https://en.wikipedia.org/wiki/Wide_character)( `/w`)，并再次检查它们的内存区域：

> 这次我们为所有与 glob 匹配的命中运行`\dm.`命令。`@@``hit5_*`

```
[0x00000000]> /w owasp-mstg
Searching 20 bytes: 6f 00 77 00 61 00 73 00 70 00 2d 00 6d 00 73 00 74 00 67 00
Searching 20 bytes in [0x0000000100708000-0x000000010096c000]
...
hits: 2
0x1020d1280 hit5_0 6f0077006100730070002d006d00730074006700
0x1030c9c85 hit5_1 6f0077006100730070002d006d00730074006700

[0x00000000]> \dm.@@ hit5_*
0x0000000102000000 - 0x0000000102100000 rw-
0x0000000103084000 - 0x00000001030cc000 rw-
```

它们位于不同的 rw- 区域。请注意，搜索宽版本的字符串有时是找到它们的唯一方法，您将在下一节中看到。

内存中搜索对于快速了解某些数据是否位于主应用程序二进制文件、共享库或其他区域中非常有用。您还可以使用它来测试应用程序关于数据如何保存在内存中的行为。例如，您可以继续前面的示例，这次单击登录并再次搜索数据的出现。另外，您可以在登录完成后检查是否仍然可以在内存中找到这些字符串，以验证这些*敏感数据*是否在使用后从内存中擦除。

##### 内存转储[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#memory-dump)

[您可以使用objection](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#objection)和[Fridump](https://github.com/Nightbringer21/fridump)转储应用程序的进程内存。要在未越狱的设备上利用这些工具，Android 应用程序必须重新打包`frida-gadget.so`并重新签名。这个过程的详细解释在“[非越狱设备的动态分析](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#dynamic-analysis-on-non-jailbroken-devices)”部分。要在越狱手机上使用这些工具，只需安装并运行 frida-server 即可。

如果反对，可以使用命令转储设备上正在运行的进程的所有内存`memory dump all`。

```
$ objection explore

iPhone on (iPhone: 10.3.1) [usb] # memory dump all /Users/foo/memory_iOS/memory
Dumping 768.0 KiB from base: 0x1ad200000  [####################################]  100%
Memory dumped to file: /Users/foo/memory_iOS/memory
```

或者你可以使用 Fridump。首先，您需要要转储的应用程序的名称，您可以使用`frida-ps`.

```
$ frida-ps -U
 PID  Name
----  ------
1026  Gadget
```

然后，在 Fridump 中指定应用名称。

```
$ python3 fridump.py -u Gadget -s

Current Directory: /Users/foo/PentestTools/iOS/fridump
Output directory is set to: /Users/foo/PentestTools/iOS/fridump/dump
Creating directory...
Starting Memory dump...
Progress: [##################################################] 100.0% Complete

Running strings on all files:
Progress: [##################################################] 100.0% Complete

Finished! Press Ctrl+C
```

当你添加`-s`标志时，所有字符串都从转储的原始内存文件中提取并添加到文件`strings.txt`中，该文件存储在 Fridump 的转储目录中。

在这两种情况下，如果您在 radare2 中打开文件，您可以使用其搜索命令 ( `/`)。请注意，首先我们进行标准字符串搜索，但没有成功，接下来我们搜索[宽字符串](https://en.wikipedia.org/wiki/Wide_character)，成功找到我们的字符串“owasp-mstg”。

```
$ r2 memory_ios
[0x00000000]> / owasp-mstg
Searching 10 bytes in [0x0-0x628c000]
hits: 0
[0x00000000]> /w owasp-mstg
Searching 20 bytes in [0x0-0x628c000]
hits: 1
0x0036f800 hit4_0 6f0077006100730070002d006d00730074006700
```

接下来，我们可以使用`s 0x0036f800` or查找它的地址`s hit4_0`并使用`psw`（代表*print string wide*）打印它或使用`px`打印它的原始十六进制值：

```
[0x0036f800]> psw
owasp-mstg

[0x0036f800]> px 48
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0036f800  6f00 7700 6100 7300 7000 2d00 6d00 7300  o.w.a.s.p.-.m.s.
0x0036f810  7400 6700 0000 0000 0000 0000 0000 0000  t.g.............
0x0036f820  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

请注意，为了使用`strings`命令找到此字符串，您必须使用`-e`标志指定编码，在本例`l`中为 16 位小端字符。

```
$ strings -e l memory_ios | grep owasp-mstg
owasp-mstg
```

##### Runtime(运行时)逆向工程[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#runtime-reverse-engineering)

Runtime(运行时)逆向工程可以看作是实时版本的逆向工程，您没有主机的二进制数据。相反，您将直接从应用程序的内存中分析它。

我们将继续使用[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)应用程序，使用 r2frida 打开一个会话，`r2 frida://usb//iGoat-Swift`您可以使用以下`\i`命令显示目标二进制信息：

```
[0x00000000]> \i
arch                arm
bits                64
os                  darwin
pid                 2166
uid                 501
objc                true
runtime             V8
java                false
cylang              true
pageSize            16384
pointerSize         8
codeSigningPolicy   optional
isDebuggerAttached  false
cwd                 /
```

搜索某个模块的所有符号`\is <lib>`，例如`\is libboringssl.dylib`。

下面对包含“aes”( ) 的符号进行不区分大小写的搜索 (grep `~+aes`)。

```
[0x00000000]> \is libboringssl.dylib~+aes
0x1863d6ed8 s EVP_aes_128_cbc
0x1863d6ee4 s EVP_aes_192_cbc
0x1863d6ef0 s EVP_aes_256_cbc
0x1863d6f14 s EVP_has_aes_hardware
0x1863d6f1c s aes_init_key
0x1863d728c s aes_cipher
0x0 u ccaes_cbc_decrypt_mode
0x0 u ccaes_cbc_encrypt_mode
...
```

或者您可能更愿意查看导入/导出。例如：

- 列出主要二进制文件的所有导入：`\ii iGoat-Swift`.
- 列出 libc++.1.dylib 库的导出：`\iE /usr/lib/libc++.1.dylib`.

> 对于大型二进制文件，建议通过附加 , 将输出传输到内部 less 程序`~..`，即`\ii iGoat-Swift~..`（如果不是，对于此二进制文件，您将在终端上打印近 5000 行）。

接下来你可能想看的是类：

```
[0x00000000]> \ic~+passcode
PSPasscodeField
_UITextFieldPasscodeCutoutBackground
UIPasscodeField
PasscodeFieldCell
...
```

列出类字段：

```
[0x19687256c]> \ic UIPasscodeField
0x000000018eec6680 - becomeFirstResponder
0x000000018eec5d78 - appendString:
0x000000018eec6650 - canBecomeFirstResponder
0x000000018eec6700 - isFirstResponder
0x000000018eec6a60 - hitTest:forEvent:
0x000000018eec5384 - setKeyboardType:
0x000000018eec5c8c - setStringValue:
0x000000018eec5c64 - stringValue
...
```

想象一下，您对`0x000000018eec5c8c - setStringValue:`. 您可以使用 查找该地址`s 0x000000018eec5c8c`，分析该函数`af`并打印其反汇编的 10 行`pd 10`：

```
[0x18eec5c8c]> pd 10
╭ (fcn) fcn.18eec5c8c 35
│   fcn.18eec5c8c (int32_t arg1, int32_t arg3);
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 2 (vars 0, args 2)
│           0x18eec5c8c      f657bd         not byte [rdi - 0x43]      ; arg1
│           0x18eec5c8f      a9f44f01a9     test eax, 0xa9014ff4
│           0x18eec5c94      fd             std
│       ╭─< 0x18eec5c95      7b02           jnp 0x18eec5c99
│       │   0x18eec5c97      a9fd830091     test eax, 0x910083fd
│           0x18eec5c9c      f30300         add eax, dword [rax]
│           0x18eec5c9f      aa             stosb byte [rdi], al
│       ╭─< 0x18eec5ca0      e003           loopne 0x18eec5ca5
│       │   0x18eec5ca2      02aa9b494197   add ch, byte [rdx - 0x68beb665] ; arg3
╰           0x18eec5ca8      f4             hlt
```

最后，您可能希望从某个二进制文件中检索字符串并过滤它们，而不是对字符串进行全内存搜索，就像您使用 radare2进行*离线操作一样。*为此，您必须找到二进制文件，寻找它，然后运行`\iz`命令。

> 建议应用带有关键字`~<keyword>`/的过滤器`~+<keyword>`以最小化终端输出。如果只想探索所有结果，您也可以将它们通过管道传输到内部 less `\iz~..`。

```
[0x00000000]> \il~iGoa
0x00000001006b8000 iGoat-Swift
[0x00000000]> s 0x00000001006b8000
[0x1006b8000]> \iz
Reading 2.390625MB ...
Do you want to print 8568 lines? (y/N) N
[0x1006b8000]> \iz~+hill
Reading 2.390625MB ...
[0x1006b8000]> \iz~+pass
Reading 2.390625MB ...
0x00000001006b93ed  "passwordTextField"
0x00000001006bb11a  "11iGoat_Swift20KeychainPasswordItemV0C5ErrorO"
0x00000001006bb164  "unexpectedPasswordData"
0x00000001006d3f62  "Error reading password from keychain - "
0x00000001006d40f2  "Incorrect Password"
0x00000001006d4112  "Enter the correct password"
0x00000001006d4632  "T@"UITextField",N,W,VpasswordField"
0x00000001006d46f2  "CREATE TABLE IF NOT EXISTS creds (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT);"
0x00000001006d4792  "INSERT INTO creds(username, password) VALUES(?, ?)"
```

要了解更多信息，请参阅[r2frida wiki](https://github.com/enovella/r2frida-wiki/blob/master/README.md)。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#references)

- Apple 的权利故障排除 - https://developer.apple.com/library/content/technotes/tn2415/_index.html
- Apple 的代码签名 - https://developer.apple.com/support/code-signing/
- Cycript 手册 - http [://www.cycript.org/manual/](http://www.cycript.org/manual/)
- 没有越狱的 iOS 工具 - https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/
- Frida iOS 教程 - https://www.frida.re/docs/ios/
- Frida iOS 示例 - https://www.frida.re/docs/examples/ios/
- r2frida 维基 - https://github.com/enovella/r2frida-wiki/blob/master/README.md
- [#miller] - Charlie Miller，Dino Dai Zovi。iOS 黑客手册。威利，2012 - [https://www.wiley.com/en-us/iOS+Hacker%27s+Handbook-p-9781118204122](https://www.wiley.com/en-us/iOS+Hacker's+Handbook-p-9781118204122)
- [#levin] 乔纳森·莱文。Mac OS X 和 iOS 内部结构：通往 Apple 的核心。威利，2013 - http://newosxbook.com/MOXiI.pdf
