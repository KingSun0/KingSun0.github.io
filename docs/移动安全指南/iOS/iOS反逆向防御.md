# iOS反逆向防御[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#ios-anti-reversing-defenses)

## 越狱检测 (MSTG-RESILIENCE-1)[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#jailbreak-detection-mstg-resilience-1)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#overview)

越狱检测机制被添加到逆向工程防御中，使应用程序在越狱设备上运行更加困难。这会阻止逆向工程师喜欢使用的一些工具和技术。与大多数其他类型的防御一样，越狱检测本身并不是很有效，但是在整个应用程序的源代码中分散检查可以提高整体防篡改方案的有效性。以下是[iOS 的典型越狱检测技术列表](https://www.trustwave.com/Resources/SpiderLabs-Blog/Jailbreak-Detection-Methods/)。

#### 基于文件的检查[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#file-based-checks)

检查通常与越狱相关的文件和目录，例如：

```
/Applications/Cydia.app
/Applications/FakeCarrier.app
/Applications/Icy.app
/Applications/IntelliScreen.app
/Applications/MxTube.app
/Applications/RockApp.app
/Applications/SBSettings.app
/Applications/WinterBoard.app
/Applications/blackra1n.app
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/MobileSubstrate.dylib
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/bin/bash
/bin/sh
/etc/apt
/etc/ssh/sshd_config
/private/var/lib/apt
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/private/var/stash
/private/var/tmp/cydia.log
/var/tmp/cydia.log
/usr/bin/sshd
/usr/libexec/sftp-server
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/var/cache/apt
/var/lib/apt
/var/lib/cydia
/usr/sbin/frida-server
/usr/bin/cycript
/usr/local/bin/cycript
/usr/lib/libcycript.dylib
/var/log/syslog
```

#### 检查文件权限[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#checking-file-permissions)

检查越狱机制的另一种方法是尝试写入应用程序沙箱之外的位置。您可以通过让应用程序尝试在例如`/private directory`. 如果文件创建成功，则设备已经越狱。

**Swift:**

```
do {
    let pathToFileInRestrictedDirectory = "/private/jailbreak.txt"
    try "This is a test.".write(toFile: pathToFileInRestrictedDirectory, atomically: true, encoding: String.Encoding.utf8)
    try FileManager.default.removeItem(atPath: pathToFileInRestrictedDirectory)
    // Device is jailbroken
} catch {
    // Device is not jailbroken
}
```

**Objective-C：**

```
NSError *error;
NSString *stringToBeWritten = @"This is a test.";
[stringToBeWritten writeToFile:@"/private/jailbreak.txt" atomically:YES
         encoding:NSUTF8StringEncoding error:&error];
if(error==nil){
   //Device is jailbroken
   return YES;
} else {
   //Device is not jailbroken
   [[NSFileManager defaultManager] removeItemAtPath:@"/private/jailbreak.txt" error:nil];
}
```

#### 检查协议处理程序[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#checking-protocol-handlers)

您可以通过尝试打开 Cydia URL 来检查协议处理程序。[Cydia](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#cydia)应用程序商店，几乎每个越狱工具都默认安装，安装 cydia:// 协议处理程序。

**Swift:**

```
if let url = URL(string: "cydia://package/com.example.package"), UIApplication.shared.canOpenURL(url) {
    // Device is jailbroken
}
```

**Objective-C：**

```
if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]){
    // Device is jailbroken
}
```

### 绕过越狱检测[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#bypassing-jailbreak-detection)

在越狱设备上启动启用了越狱检测的应用程序后，您可能会注意到以下情况之一：

1. 应用程序立即关闭，没有任何通知。
2. 弹出窗口指示应用程序不会在越狱设备上运行。

在第一种情况下，请确保应用程序在未越狱的设备上功能齐全。应用程序可能正在崩溃，或者它可能有导致它终止的错误。当您测试应用程序的预生产版本时，可能会发生这种情况。

[让我们再次以Damn Vulnerable iOS 应用程序](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#dvia-v2)为例来绕过越狱检测。将二进制文件加载到[Hopper](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#hopper-commercial-tool)（商业工具）后，您需要等到应用程序完全反汇编（查看顶部栏以检查状态）。然后在搜索框中查找“jail”字符串。你会看到两个类：`SFAntiPiracy`和`JailbreakDetectionVC`。您可能想要反编译这些函数以查看它们在做什么，尤其是它们返回的内容。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/HopperDisassembling.png) ![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/HopperDecompile.png)

如您所见，有一个类方法 ( `+[SFAntiPiracy isTheDeviceJailbroken]`) 和一个实例方法 ( `-[JailbreakDetectionVC isJailbroken]`)。主要区别在于我们可以在应用程序中注入Cycript并直接调用类方法，而实例方法需要先寻找目标类的实例。该函数`choose`将在内存堆中查找给定类的已知签名，并返回一个实例数组。将应用程序置于所需状态（以便类确实被实例化）很重要。

让我们将 Cycript 注入我们的进程（使用 查找您的 PID `top`）：

```
iOS8-jailbreak:~ root# cycript -p 12345
cy# [SFAntiPiracy isTheDeviceJailbroken]
true
```

如您所见，我们的类方法被直接调用，并返回“true”。现在，让我们调用`-[JailbreakDetectionVC isJailbroken]`实例方法。首先，我们必须调用`choose`函数来查找`JailbreakDetectionVC`类的实例。

```
cy# a=choose(JailbreakDetectionVC)
[]
```

哎呀！返回值是一个空数组。这意味着在Runtime(运行时)中没有注册此类的实例。事实上，我们还没有点击第二个“越狱测试”按钮，它初始化了这个类：

```
cy# a=choose(JailbreakDetectionVC)
[#"<JailbreakDetectionVC: 0x14ee15620>"]
cy# [a[0] isJailbroken]
True
```

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/deviceISjailbroken.png)

现在您明白为什么让您的应用程序处于所需状态很重要了。在这一点上，使用 Cycript 绕过越狱检测是微不足道的。我们可以看到该函数返回一个布尔值；我们只需要替换返回值。我们可以通过用 Cycript 替换函数实现来替换返回值。请注意，这实际上将替换其给定名称下的函数，因此如果该函数修改了应用程序中的任何内容，请注意副作用：

```
cy# JailbreakDetectionVC.prototype.isJailbroken=function(){return false}
cy# [a[0] isJailbroken]
false
```

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/deviceisNOTjailbroken.png)

在这种情况下，我们已经绕过了应用程序的越狱检测！

现在，假设应用程序在检测到设备已越狱后立即关闭。您没有时间启动 Cycript 并替换函数实现。相反，您必须使用 CydiaSubstrate，使用适当的Hook函数（如`MSHookMessageEx`），然后编译调整。关于如何做到这一点有[很好的资源；](https://manualzz.com/doc/26490749/jailbreak-root-detection-evasion-study-on-ios-and-android)但是，通过使用 Frida，我们可以更轻松地执行早期检测，并且可以利用从之前的测试中收集到的技能。

我们将用来绕过越狱检测的 Frida 的一项功能是所谓的早期检测，即我们将在启动时替换功能实现。

1. 确保它`frida-server`正在您的 iOS 设备上运行。
2. 确保它`Frida`已[安装](https://www.frida.re/docs/installation/)在您的主机上。
3. iOS 设备必须通过 USB 数据线连接。
4. `frida-trace`在您的主机上使用：

```
frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]"
```

这将启动 DamnVulnerableIOSApp，跟踪对 的调用，并使用和回调函数`-[JailbreakDetectionVC isJailbroken]`创建一个 JavaScript Hook。现在，替换返回值 via是微不足道的，如以下示例所示：`onEnter``onLeave``value.replace`

```
    onLeave: function (log, retval, state) {
    console.log("Function [JailbreakDetectionVC isJailbroken] originally returned:"+ retval);
    retval.replace(0);  
      console.log("Changing the return value to:"+retval);
    }
```

这将提供以下输出：

```
$ frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]:"

Instrumenting functions...                                           `...
-[JailbreakDetectionVC isJailbroken]: Loaded handler at "./__handlers__/__JailbreakDetectionVC_isJailbroken_.js"
Started tracing 1 function. Press Ctrl+C to stop.
Function [JailbreakDetectionVC isJailbroken] originally returned:0x1
Changing the return value to:0x0
           /* TID 0x303 */
  6890 ms  -[JailbreakDetectionVC isJailbroken]
Function [JailbreakDetectionVC isJailbroken] originally returned:0x1
Changing the return value to:0x0
 22475 ms  -[JailbreakDetectionVC isJailbroken]
```

请注意对 的两次调用`-[JailbreakDetectionVC isJailbroken]`，它们对应于应用程序 GUI 上的两次物理点击。

绕过依赖于文件系统检查的越狱检测机制的另一种方法是[反对](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#objection)。[您可以在jailbreak.ts 脚本](https://github.com/sensepost/objection/blob/master/agent/src/ios/jailbreak.ts)中找到越狱绕过的实现。

请参阅下面用于挂接 Objective-C 方法和Native函数的 Python 脚本：

```
import frida
import sys

try:
    session = frida.get_usb_device().attach("Target Process")
except frida.ProcessNotFoundError:
    print "Failed to attach to the target process. Did you launch the app?"
    sys.exit(0)

script = session.create_script("""

    // Handle fork() based check

    var fork = Module.findExportByName("libsystem_c.dylib", "fork");

    Interceptor.replace(fork, new NativeCallback(function () {
        send("Intercepted call to fork().");
        return -1;
    }, 'int', []));

    var system = Module.findExportByName("libsystem_c.dylib", "system");

    Interceptor.replace(system, new NativeCallback(function () {
        send("Intercepted call to system().");
        return 0;
    }, 'int', []));

    // Intercept checks for Cydia URL handler

    var canOpenURL = ObjC.classes.UIApplication["- canOpenURL:"];

    Interceptor.attach(canOpenURL.implementation, {
        onEnter: function(args) {
          var url = ObjC.Object(args[2]);
          send("[UIApplication canOpenURL:] " + path.toString());
          },
        onLeave: function(retval) {
            send ("canOpenURL returned: " + retval);
        }

    });

    // Intercept file existence checks via [NSFileManager fileExistsAtPath:]

    var fileExistsAtPath = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
    var hideFile = 0;

    Interceptor.attach(fileExistsAtPath.implementation, {
        onEnter: function(args) {
          var path = ObjC.Object(args[2]);
          // send("[NSFileManager fileExistsAtPath:] " + path.toString());

          if (path.toString() == "/Applications/Cydia.app" || path.toString() == "/bin/bash") {
            hideFile = 1;
          }
        },
        onLeave: function(retval) {
            if (hideFile) {
                send("Hiding jailbreak file...");MM
                retval.replace(0);
                hideFile = 0;
            }

            // send("fileExistsAtPath returned: " + retval);
      }
    });


    /* If the above doesn't work, you might want to hook low level file APIs as well

        var openat = Module.findExportByName("libsystem_c.dylib", "openat");
        var stat = Module.findExportByName("libsystem_c.dylib", "stat");
        var fopen = Module.findExportByName("libsystem_c.dylib", "fopen");
        var open = Module.findExportByName("libsystem_c.dylib", "open");
        var faccesset = Module.findExportByName("libsystem_kernel.dylib", "faccessat");

    */

""")

def on_message(message, data):
    if 'payload' in message:
            print(message['payload'])

script.on('message', on_message)
script.load()
sys.stdin.read()
```

## 测试反调试检测（MSTG-RESILIENCE-2）[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#testing-anti-debugging-detection-mstg-resilience-2)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#overview_1)

在逆向过程中，使用调试器探索应用程序是一项非常强大的技术。您不仅可以跟踪包含敏感数据的变量和修改应用程序的控制流，还可以读取和修改内存和寄存器。

有几种适用于 iOS 的反调试技术可以归类为预防性或反应性；下面讨论其中的一些。作为第一道防线，您可以使用预防技术来阻止调试器连接到应用程序。此外，您还可以应用反应性技术，允许应用程序检测调试器的存在并有机会偏离正常行为。当在整个应用程序中正确分布时，这些技术可作为辅助或支持措施来提高整体弹性。

处理高度敏感数据的应用程序的应用程序开发人员应该意识到，防止调试几乎是不可能的。如果应用程序是公开可用的，它可以在攻击者完全控制的不受信任的设备上运行。一个非常坚定的攻击者最终会通过修补应用程序二进制文件或使用 Frida 等工具在Runtime(运行时)动态修改应用程序的行为来设法绕过应用程序的所有反调试控制。

根据 Apple 的说法，您应该“[将上述代码的使用限制在程序的调试版本中](https://developer.apple.com/library/archive/qa/qa1361/_index.html)”。然而，研究表明，[许多 App Store 应用程序通常包含这些检查](https://seredynski.com/articles/a-security-review-of-1300-appstore-applications.html)。

#### 使用 ptrace[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#using-ptrace)

如“ [iOS 上的篡改和逆向工程](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#debugging)”一章所示，iOS XNU 内核实现了一个`ptrace`系统调用，该系统调用缺少正确调试进程所需的大部分功能（例如，它允许附加/步进但不允许读/写内存和寄存器） .

尽管如此，系统调用的 iOS 实现`ptrace`包含一个非标准但非常有用的功能：防止进程调试。此功能作为`PT_DENY_ATTACH`请求实现，如[官方 BSD 系统调用手册](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html)中所述。简而言之，它确保没有其他调试器可以附加到调用进程；如果调试器尝试附加，进程将终止。Using`PT_DENY_ATTACH`是一个相当知名的反调试技术，所以你在 iOS 渗透测试中可能会经常遇到它。

> 在深入细节之前，重要的是要知道它`ptrace`不是公共 iOS API 的一部分。禁止使用非公开 API，App Store 可能会拒绝包含它们的应用。因此，`ptrace`在代码中没有直接调用；当`ptrace`通过 获得函数指针时调用它`dlsym`。

以下是上述逻辑的示例实现：

```
#import <dlfcn.h>
#import <sys/types.h>
#import <stdio.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
void anti_debug() {
  ptrace_ptr_t ptrace_ptr = (ptrace_ptr_t)dlsym(RTLD_SELF, "ptrace");
  ptrace_ptr(31, 0, 0, 0); // PTRACE_DENY_ATTACH = 31
}
```

为了演示如何绕过这种技术，我们将使用一个实现这种方法的反汇编二进制文件的示例：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/ptraceDisassembly.png)

让我们分解二进制文件中发生的事情。作为第二个参数（寄存器 R1）`dlsym`被调用。`ptrace`寄存器 R0 中的返回值被移动到寄存器 R6 的偏移量 0x1908A 处。在偏移量 0x19098 处，使用 BLX R6 指令调用寄存器 R6 中的指针值。要禁用`ptrace`调用，我们需要将指令`BLX R6`( `0xB0 0x47`in Little Endian) 替换为`NOP`( `0x00 0xBF`in Little Endian) 指令。打补丁后，代码将类似于以下内容：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/ptracePatched.png)

[Armconverter.com](http://armconverter.com/)是一个方便的字节码和指令助记符之间转换的工具。

其他基于 ptrace 的反调试技术的绕过可以在[Alexander O'Mara 的“击败反调试技术：macOS ptrace 变体”中](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)找到。

#### 使用 sysctl[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#using-sysctl)

检测附加到调用进程的调试器的另一种方法涉及`sysctl`. 根据 Apple 文档，它允许进程设置系统信息（如果具有适当的权限）或简单地检索系统信息（例如进程是否正在调试）。但是，请注意，应用程序使用的事实`sysctl`可能是反调试控件的指示器，尽管情况[并非总是如此](http://www.cocoawithlove.com/blog/2016/03/08/swift-wrapper-for-sysctl.html)。

[Apple 文档存档](https://developer.apple.com/library/content/qa/qa1361/_index.html)中的以下示例使用适当的参数检查`info.kp_proc.p_flag`调用返回的标志：`sysctl`

```
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>

static bool AmIBeingDebugged(void)
    // Returns true if the current process is being debugged (either
    // running under the debugger or has a debugger attached post facto).
{
    int                 junk;
    int                 mib[4];
    struct kinfo_proc   info;
    size_t              size;

    // Initialize the flags so that, if sysctl fails for some bizarre
    // reason, we get a predictable result.

    info.kp_proc.p_flag = 0;

    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    // Call sysctl.

    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);

    // We're being debugged if the P_TRACED flag is set.

    return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
}
```

绕过此检查的一种方法是修补二进制文件。上面的代码编译后，后半部分代码的反汇编版本类似如下：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/sysctlOriginal.png)

将偏移量0xC13C处的指令`MOVNE R0, #1`打补丁修改为`MOVNE R0, #0`字节码中的(0x00 0x20 in)，打补丁后的代码类似如下：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/sysctlPatched.png)

您还可以`sysctl`通过使用调试器本身并在对 的调用处设置断点来绕过检查`sysctl`。此方法在[iOS 反调试保护 #2](https://www.coredump.gr/articles/ios-anti-debugging-protections-part-2/)中进行了演示。

### 使用 getppid[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#using-getppid)

iOS 上的应用程序可以通过检查其父 PID 来检测它们是否已被调试器启动。通常，一个应用程序是由[launchd](http://newosxbook.com/articles/Ch07.pdf)进程启动的，它是第一个运行在*用户模式下*的进程， PID=1。然而，如果调试器启动了一个应用程序，我们可以观察到它`getppid`返回一个不同于 1 的 PID。这种检测技术可以在Native代码中实现（通过系统调用），使用 Objective-C 或 Swift，如下所示：

```
func AmIBeingDebugged() -> Bool {
    return getppid() != 1
}
```

与其他技术类似，这也有一个简单的绕过（例如，通过修补二进制文件或使用 Frida Hook）。

## 文件完整性检查（MSTG-RESILIENCE-3 和 MSTG-RESILIENCE-11）[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#file-integrity-checks-mstg-resilience-3-and-mstg-resilience-11)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#overview_2)

有两个与文件完整性相关的主题：

1. *应用程序源代码完整性检查：*在“ [iOS 上的篡改和逆向工程](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#debugging)”一章中，我们讨论了 iOS IPA 应用程序签名检查。我们还看到坚定的逆向工程师可以通过使用开发人员或企业证书重新打包和重新签署应用程序来绕过此检查。使这更难的一种方法是添加一个自定义检查，以确定签名在Runtime(运行时)是否仍然匹配。
2. *文件存储完整性检查：*`UserDefaults`当文件被应用程序、Keychain、 / 、SQLite 数据库或 Realm 数据库中的键值对存储时，`NSUserDefaults`应保护其完整性。

#### 示例实现 - 应用程序源代码[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#sample-implementation-application-source-code)

Apple 负责使用 DRM 进行完整性检查。然而，额外的控制（例如在下面的例子中）是可能的。`mach_header`解析以计算用于生成签名的指令数据的开始。接下来，将签名与给定的签名进行比较。确保生成的签名在其他地方存储或编码。

```
int xyz(char *dst) {
    const struct mach_header * header;
    Dl_info dlinfo;

    if (dladdr(xyz, &dlinfo) == 0 || dlinfo.dli_fbase == NULL) {
        NSLog(@" Error: Could not resolve symbol xyz");
        [NSThread exit];
    }

    while(1) {

        header = dlinfo.dli_fbase;  // Pointer on the Mach-O header
        struct load_command * cmd = (struct load_command *)(header + 1); // First load command
        // Now iterate through load command
        //to find __text section of __TEXT segment
        for (uint32_t i = 0; cmd != NULL && i < header->ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT) {
                // __TEXT load command is a LC_SEGMENT load command
                struct segment_command * segment = (struct segment_command *)cmd;
                if (!strcmp(segment->segname, "__TEXT")) {
                    // Stop on __TEXT segment load command and go through sections
                    // to find __text section
                    struct section * section = (struct section *)(segment + 1);
                    for (uint32_t j = 0; section != NULL && j < segment->nsects; j++) {
                        if (!strcmp(section->sectname, "__text"))
                            break; //Stop on __text section load command
                        section = (struct section *)(section + 1);
                    }
                    // Get here the __text section address, the __text section size
                    // and the virtual memory address so we can calculate
                    // a pointer on the __text section
                    uint32_t * textSectionAddr = (uint32_t *)section->addr;
                    uint32_t textSectionSize = section->size;
                    uint32_t * vmaddr = segment->vmaddr;
                    char * textSectionPtr = (char *)((int)header + (int)textSectionAddr - (int)vmaddr);
                    // Calculate the signature of the data,
                    // store the result in a string
                    // and compare to the original one
                    unsigned char digest[CC_MD5_DIGEST_LENGTH];
                    CC_MD5(textSectionPtr, textSectionSize, digest);     // calculate the signature
                    for (int i = 0; i < sizeof(digest); i++)             // fill signature
                        sprintf(dst + (2 * i), "%02x", digest[i]);

                    // return strcmp(originalSignature, signature) == 0;    // verify signatures match

                    return 0;
                }
            }
            cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
        }
    }

}
```

#### 示例实施 - 存储[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#sample-implementation-storage)

在确保应用程序存储本身的完整性时，您可以在给定的键值对或存储在设备上的文件上创建 HMAC 或签名。CommonCrypto 实现最适合创建 HMAC。如果您需要加密，请确保先加密，然后再按经过[身份验证的加密](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html)中所述进行 HMAC 。

使用 CC 生成 HMAC 时：

1. 获取数据为`NSMutableData`.
2. 获取数据密钥（如果可能，从钥匙串中获取）。
3. 计算哈希值。
4. 将散列值附加到实际数据。
5. 存储步骤 4 的结果。

```
    // Allocate a buffer to hold the digest and perform the digest.
    NSMutableData* actualData = [getData];
    //get the key from the keychain
    NSData* key = [getKey];
    NSMutableData* digestBuffer = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, [actualData bytes], (CC_LONG)[key length], [actualData bytes], (CC_LONG)[actualData length], [digestBuffer mutableBytes]);
    [actualData appendData: digestBuffer];
```

或者，您可以在第 1 步和第 3 步中使用 NSData，但您需要为第 4 步创建一个新缓冲区。

使用 CC 验证 HMAC 时，请按照以下步骤操作：

1. 将消息和 hmacbytes 提取为单独的`NSData`.
2. 重复在 上生成 HMAC 过程的步骤 1-3 `NSData`。
3. 将提取的 HMAC 字节与步骤 1 的结果进行比较。

```
  NSData* hmac = [data subdataWithRange:NSMakeRange(data.length - CC_SHA256_DIGEST_LENGTH, CC_SHA256_DIGEST_LENGTH)];
  NSData* actualData = [data subdataWithRange:NSMakeRange(0, (data.length - hmac.length))];
  NSMutableData* digestBuffer = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, [actualData bytes], (CC_LONG)[key length], [actualData bytes], (CC_LONG)[actualData length], [digestBuffer mutableBytes]);
  return [hmac isEqual: digestBuffer];
```

#### 绕过文件完整性检查[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#bypassing-file-integrity-checks)

##### 当您试图绕过应用程序源完整性检查时[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#when-youre-trying-to-bypass-the-application-source-integrity-checks)

1. 修补反调试功能并通过用 NOP 指令覆盖相关代码来禁用不需要的行为。
2. 修补任何用于评估代码完整性的存储散列。
3. 使用 Frida Hook文件系统 API 并返回原始文件的句柄而不是修改后的文件。

##### 当您试图绕过存储完整性检查时[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#when-youre-trying-to-bypass-the-storage-integrity-checks)

1. 如“[设备绑定](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#device-binding-mstg-resilience-10)”部分所述，从设备中检索数据。
2. 更改检索到的数据并将其返回存储。

### 成效评估[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#effectiveness-assessment)

**应用程序源代码完整性检查：**

以未修改的状态在设备上运行应用程序，并确保一切正常。然后使用 optool 将补丁应用到可执行文件，按照“基本安全测试”一章中的描述重新签署应用程序，然后运行它。该应用程序应检测到修改并以某种方式做出响应。至少，应用程序应该提醒用户和/或终止应用程序。绕过防御并回答以下问题：

- 是否可以轻松绕过这些机制（例如，通过Hook单个 API 函数）？
- 通过静态和动态分析识别反调试代码有多难？
- 您是否需要编写自定义代码来禁用防御？你需要多少时间？
- 您如何评估绕过这些机制的难度？

**存储完整性检查：**

类似的方法有效。回答以下问题：

- 是否可以轻松绕过这些机制（例如，通过更改文件或键值对的内容）？
- 获取 HMAC 密钥或非对称私钥有多难？
- 您是否需要编写自定义代码来禁用防御？你需要多少时间？
- 您如何评估绕过这些机制的难度？

## 测试逆向工程工具检测 (MSTG-RESILIENCE-4)[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#testing-reverse-engineering-tools-detection-mstg-resilience-4)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#overview_3)

逆向工程师常用的工具、框架和应用程序的存在可能表明有人试图对应用程序进行逆向工程。其中一些工具只能在越狱设备上运行，而另一些工具则强制应用程序进入调试模式或依赖于在手机上启动后台服务。因此，应用程序可以通过不同的方式来检测逆向工程攻击并对其做出反应，例如通过终止自身。

### 检测方法[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#detection-methods)

您可以通过查找关联的应用程序包、文件、进程或其他特定于工具的修改和工件来检测以未修改形式安装的流行逆向工程工具。在以下示例中，我们将讨论检测 Frida 检测框架的不同方法，该框架在本指南和现实世界中得到广泛使用。其他工具，如Cydia Substrate或Cycript，也可以类似检测。请注意，注入、Hook和 DBI（动态二进制检测）工具通常可以通过Runtime(运行时)完整性检查隐式检测到，这将在下面讨论。

例如，Frida 在越狱设备上以默认配置（注入模式）以 frida-server 的名称运行。当您显式附加到目标应用程序时（例如，通过 frida-trace 或 Frida CLI），Frida 会在应用程序的内存中注入一个 frida-agent。因此，您可能希望在附加到应用程序之后（而不是之前）找到它。`proc`在 Android 上，验证这一点非常简单，因为您可以简单地在目录 ( `/proc/<pid>/maps`)中进程 ID 的内存映射中查找字符串“frida” 。但是，在 iOS 上该`proc`目录不可用，但您可以使用函数列出应用程序中加载的动态库`_dyld_image_count`。

Frida 也可以在所谓的嵌入式模式下运行，该模式也适用于非越狱设备。它包括将一个[frida-gadget](https://www.frida.re/docs/gadget/)嵌入到 IPA 中，并*强制*应用程序将其作为其原生库之一加载。

应用程序的静态内容（包括其 ARM 编译的二进制文件及其外部库）存储在该`<Application>.app`目录中。如果您检查`/var/containers/Bundle/Application/<UUID>/<Application>.app`目录的内容，您会发现嵌入的 frida-gadget 作为 FridaGadget.dylib。

```
iPhone:/var/containers/Bundle/Application/AC5DC1FD-3420-42F3-8CB5-E9D77C4B287A/SwiftSecurity.app/Frameworks root# ls -alh
total 87M
drwxr-xr-x 10 _installd _installd  320 Nov 19 06:08 ./
drwxr-xr-x 11 _installd _installd  352 Nov 19 06:08 ../
-rw-r--r--  1 _installd _installd  70M Nov 16 06:37 FridaGadget.dylib
-rw-r--r--  1 _installd _installd 3.8M Nov 16 06:37 libswiftCore.dylib
-rw-r--r--  1 _installd _installd  71K Nov 16 06:37 libswiftCoreFoundation.dylib
-rw-r--r--  1 _installd _installd 136K Nov 16 06:38 libswiftCoreGraphics.dylib
-rw-r--r--  1 _installd _installd  99K Nov 16 06:37 libswiftDarwin.dylib
-rw-r--r--  1 _installd _installd 189K Nov 16 06:37 libswiftDispatch.dylib
-rw-r--r--  1 _installd _installd 1.9M Nov 16 06:38 libswiftFoundation.dylib
-rw-r--r--  1 _installd _installd  76K Nov 16 06:37 libswiftObjectiveC.dylib
```

看着Frida*留下的这些**痕迹*，你可能已经想象到检测 Frida 将是一件微不足道的任务。虽然检测这些库是微不足道的，但绕过这种检测也同样微不足道。工具检测是一场猫捉老鼠的游戏，事情会变得更加复杂。下表简要介绍了一组典型的 Frida 检测方法，并简要讨论了它们的有效性。

> [iOS Security Suite](https://github.com/securing/IOSSecuritySuite)中实现了以下一些检测方法。

| 方法                           | 描述                                                         | 讨论                                                         |
| :----------------------------- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| **检查相关工件的环境**         | 工件可以是打包文件、二进制文件、库、进程和临时文件。对于 Frida，这可能是在目标（越狱）系统中运行的 frida-server（负责通过 TCP 公开 Frida 的守护进程）或应用程序加载的 frida 库。 | 对于未越狱设备上的 iOS 应用程序，无法检查正在运行的服务。iOS 上没有Swift 方法[CommandLine](https://developer.apple.com/documentation/swift/commandline)来查询正在运行的进程的信息，但是有一些非官方的方法，比如使用[NSTask](https://stackoverflow.com/a/56619466). 然而，使用这种方法时，应用程序将在 App Store 审核过程中被拒绝。没有其他公共 API 可用于查询正在运行的进程或在 iOS 应用程序中执行系统命令。即使有可能，绕过它也很容易，只需重命名相应的 Frida 工件 (frida-server/frida-gadget/frida-agent)。另一种检测 Frida 的方法是遍历已加载库的列表并检查可疑库（例如名称中包含“frida”的库），这可以通过使用`_dyld_get_image_name`. |
| **检查打开的 TCP 端口**        | frida-server 进程默认绑定到 TCP 端口 27042。测试此端口是否打开是检测守护进程的另一种方法。 | 此方法在其默认模式下检测 frida-server，但可以通过命令行参数更改监听端口，因此绕过它非常简单。 |
| **检查响应 D-Bus Auth 的端口** | `frida-server`使用 D-Bus 协议进行通信，因此您可以期望它响应 D-Bus AUTH。向每个打开的端口发送一条 D-Bus AUTH 消息并检查答案，希望它`frida-server`会自己显示出来。 | 这是一种相当可靠的检测方法`frida-server`，但 Frida 提供了不需要 frida-server 的替代操作模式。 |

请记住，这张表远非详尽无遗。例如，另外两种可能的检测机制是：

- [命名管道](https://en.wikipedia.org/wiki/Named_pipe)（由 frida-server 用于外部通信），或
- 检测[蹦床](https://en.wikipedia.org/wiki/Trampoline_(computing))（请参阅“[防止绕过 iOS 应用程序中的 SSL 证书固定](https://www.guardsquare.com/en/blog/iOS-SSL-certificate-pinning-bypassing)”以获得进一步的解释和用于检测 iOS 应用程序中的蹦床的示例代码）

两者都*有助于*检测 Substrate 或 Frida 的拦截器，但例如，对 Frida 的 Stalker 无效。请记住，这些检测方法中的每一种是否成功取决于您是否使用越狱设备、越狱和方法的特定版本和/或工具本身的版本。最后，这是保护在不受控制的环境（最终用户的设备）上处理的数据的猫捉老鼠游戏的一部分。

> 重要的是要注意，这些控制只会增加逆向工程过程的复杂性。如果使用，最好的方法是巧妙地组合控件而不是单独使用它们。然而，它们都不能保证 100% 的有效性，因为逆向工程师总是可以完全访问设备，因此总是会赢！您还必须考虑将某些控件集成到您的应用程序中可能会增加应用程序的复杂性，甚至会影响其性能。

### 成效评估[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#effectiveness-assessment_1)

使用安装在测试设备上的各种逆向工程工具和框架启动应用程序。至少包括以下内容：Frida、Cydia Substrate、Cycript 和 SSL Kill Switch。

该应用程序应以某种方式响应这些工具的存在。例如：

- 提醒用户并要求承担责任。
- 通过优雅终止来防止执行。
- 安全擦除存储在设备上的任何敏感数据。
- 向后端服务器报告，例如，用于欺诈检测。

接下来，绕过逆向工程工具的检测并回答以下问题：

- 是否可以轻松绕过这些机制（例如，通过Hook单个 API 函数）？
- 通过静态和动态分析识别反逆向工程代码有多难？
- 您是否需要编写自定义代码来禁用防御？你需要多少时间？
- 您如何评估绕过这些机制的难度？

绕过逆向工程工具的检测时，应遵循以下步骤：

1. 修补反逆向工程功能。通过使用 radare2/Cutter 或 Ghidra 修补二进制文件来禁用不需要的行为。
2. 使用 Frida 或 Cydia Substrate 在 Objective-C/Swift 或Native层上挂接文件系统 API。返回原始文件的句柄，而不是修改后的文件。

有关修补和代码注入的示例，请参阅“ [iOS 上](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/)的篡改和逆向工程”一章。

## 测试仿真器检测 (MSTG-RESILIENCE-5)[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#testing-emulator-detection-mstg-resilience-5)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#overview_4)

模拟器检测的目标是增加在模拟设备上运行应用程序的难度。这迫使逆向工程师绕过仿真器检查或利用物理设备，从而禁止进行大规模设备分析所需的访问。

正如在基本安全测试一章[的 iOS 模拟器](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/)测试一节中所讨论的，唯一可用的模拟器是 Xcode 附带的模拟器。模拟器二进制文件被编译为 x86 代码而不是 ARM 代码，并且为真实设备（ARM 体系结构）编译的应用程序不会在模拟器中运行，因此与具有广泛范围的 Android 相比，iOS 应用程序的*模拟*保护不是那么重要可用的*仿真*选择。

然而，自发布以来，[Corellium](https://www.corellium.com/)（商业工具）启用了真正的仿真，[将自己与 iOS 模拟器区分开来](https://www.corellium.com/compare/ios-simulator)。除此之外，作为 SaaS 解决方案，Corellium 支持大规模设备分析，限制因素只是可用资金。

随着 Apple Silicon (ARM) 硬件的广泛应用，传统的 x86 / x64 架构检查可能已经不够用了。一种潜在的检测策略是识别常用仿真解决方案可用的功能和限制。例如，Corellium 不支持 iCloud、蜂窝服务、相机、NFC、蓝牙、App Store 访问或 GPU 硬件仿真 ( [Metal](https://developer.apple.com/documentation/metal/gpu_devices_and_work_submission/getting_the_default_gpu) )。因此，巧妙地结合涉及任何这些功能的检查可能是模拟环境存在的指标。

将这些结果与[iOS Security Suite](https://github.com/securing/IOSSecuritySuite#emulator-detector-module)、[Trusteer等第 3 方框架或](https://www.ibm.com/products/trusteer-mobile-sdk/details)[Appdome](https://www.appdome.com/) （商业解决方案）等无代码解决方案的结果进行配对，可以很好地防御利用模拟器的攻击。

## 测试混淆 (MSTG-RESILIENCE-9)[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#testing-obfuscation-mstg-resilience-9)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#overview_5)

[“移动应用程序篡改和逆向工程”](https://mas.owasp.org/MASTG/General/0x04c-Tampering-and-Reverse-Engineering/#obfuscation)一章介绍了几种众所周知的混淆技术，通常可以在移动应用程序中使用。

> 注意：下面介绍的所有技术可能不会阻止逆向工程师，但结合所有这些技术将使他们的工作变得更加困难。这些技术的目的是阻止逆向工程师进行进一步的分析。

以下技术可用于混淆应用程序：

- 名称混淆
- 指令替换
- 控制流扁平化
- 死代码注入
- 字符串加密

### 名称混淆[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#name-obfuscation)

标准编译器根据源代码中的类名和函数名生成二进制符号。因此，如果没有应用混淆，符号名称仍然有意义并且可以很容易地直接从应用程序二进制文件中读取。例如，可以通过搜索相关关键字（例如“越狱”）来定位检测越狱的功能。下面的清单显示了`JailbreakDetectionViewController.jailbreakTest4Tapped`该死的易受攻击的 iOS 应用程序 ( [DVIA-v2](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#dvia-v2) ) 的反汇编函数。

```
__T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest4TappedyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

混淆之后，我们可以观察到符号的名称不再有意义，如下面的清单所示。

```
__T07DVIA_v232zNNtWKQptikYUBNBgfFVMjSkvRdhhnbyyFySbyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

然而，这仅适用于函数、类和字段的名称。实际代码保持不变，因此攻击者仍然可以阅读函数的反汇编版本并尝试理解其目的（例如检索安全算法的逻辑）。

### 指令替换[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#instruction-substitution)

这种技术用更复杂的表示形式取代了标准的二元运算符，如加法或减法。例如，加法`x = a + b`可以表示为`x = -(-a) - (-b)`。然而，使用相同的替换表示很容易被逆转，因此建议为单个案例添加多个替换技术并引入随机因素。这种技术容易受到反混淆的影响，但根据替换的复杂性和深度，应用它仍然可能很耗时。

### 控制流扁平化[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#control-flow-flattening)

控制流扁平化用更复杂的表示替换了原始代码。转换将函数体分解为基本块，并将它们全部放入一个无限循环中，并使用控制程序流的 switch 语句。这使得程序流程明显更难遵循，因为它删除了通常使代码更易于阅读的自然条件结构。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/control-flow-flattening.png)

该图显示了控制流扁平化如何改变代码（参见“ [Obfuscating C++ programs via control flow flattening](http://ac.inf.elte.hu/Vol_030_2009/003.pdf) ”）

### 死代码注入[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#dead-code-injection)

这种技术通过将死代码注入程序，使程序的控制流更加复杂。死代码是一种代码存根，它不会影响原始程序的行为，但会增加逆向工程过程的开销。

### 字符串加密[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#string-encryption)

应用程序通常使用硬编码密钥、Licenses（许可证）、令牌和端点 URL 进行编译。默认情况下，所有这些都以明文形式存储在应用程序二进制文件的数据部分中。此技术加密这些值并将代码存根注入程序，程序将在程序使用数据之前对其进行解密。

### 推荐工具[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#recommended-tools)

- [SwiftShield](https://github.com/rockbruno/swiftshield)可用于执行名称混淆。它读取 Xcode 项目的源代码，并在使用编译器之前用随机值替换所有类名、方法名和字段名。
- [obfuscator-llvm](https://github.com/obfuscator-llvm)在中间表示 (IR) 而不是源代码上运行。它可用于符号混淆、字符串加密和控制流扁平化。由于它基于 IR，因此与 SwiftShield 相比，它可以隐藏更多关于应用程序的信息。

[在此处](https://faculty.ist.psu.edu/wu/papers/obf-ii.pdf)了解有关 iOS 混淆技术的更多信息。

#### 如何使用 SwiftShield[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#how-to-use-swiftshield)

> 警告：SwiftShield 不可逆转地覆盖所有源文件。理想情况下，你应该让它只在你的 CI 服务器和发布版本上运行。

[SwiftShield](https://github.com/rockbruno/swiftshield)是一种工具，可以为您的 iOS 项目对象（包括您的 Pod 和故事板）生成不可逆的加密名称。这提高了逆向工程的门槛，并且在使用逆向工程工具（例如 class-dump 和 Frida）时会产生较少有用的输出。

示例 Swift 项目用于演示 SwiftShield 的用法。

- 查看https://github.com/sushi2k/SwiftSecurity。
- 在 Xcode 中打开项目并确保项目构建成功（Product / Build 或 Apple-Key + B）。
- [下载](https://github.com/rockbruno/swiftshield/releases)最新版本的 SwiftShield 并解压缩。
- 转到下载 SwiftShield 的目录并将 swiftshield 可执行文件复制到`/usr/local/bin`：

```
cp swiftshield/swiftshield /usr/local/bin/
```

- 在您的终端中进入 SwiftSecurity 目录（您在第 1 步中检出）并执行命令 swiftshield（您在第 3 步中下载）：

```
$ cd SwiftSecurity
$ swiftshield -automatic -project-root . -automatic-project-file SwiftSecurity.xcodeproj -automatic-project-scheme SwiftSecurity
SwiftShield 3.4.0
Automatic mode
Building project to gather modules and compiler arguments...
-- Indexing ReverseEngineeringToolsChecker.swift --
Found declaration of ReverseEngineeringToolsChecker (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC)
Found declaration of amIReverseEngineered (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC20amIReverseEngineeredSbyFZ)
Found declaration of checkDYLD (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC9checkDYLD33_D6FE91E9C9AEC4D13973F8ABFC1AC788LLSbyFZ)
Found declaration of checkExistenceOfSuspiciousFiles (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC31checkExistenceOfSuspiciousFiles33_D6FE91E9C9AEC4D13973F8ABFC1AC788LLSbyFZ)
...
```

SwiftShield 现在正在检测类和方法名称，并将它们的标识符替换为加密值。

在原始源代码中，您可以看到所有的类和方法标识符：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/no_obfuscation.jpg)

SwiftShield 现在用加密值替换了所有这些值，这些值不会留下任何痕迹到它们的原始名称或类/方法的意图：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06j/swiftshield_obfuscated.jpg)

执行`swiftshield`后将创建一个名为`swiftshield-output`. 在此目录中创建了另一个目录，其文件夹名称中带有时间戳。该目录包含一个名为 的文本文件`conversionMap.txt`，它将加密的字符串映射到它们的原始值。

```
$ cat conversionMap.txt
//
// SwiftShield Conversion Map
// Automatic mode for SwiftSecurity, 2020-01-02 13.51.03
// Deobfuscate crash logs (or any text file) by running:
// swiftshield -deobfuscate CRASH_FILE -deobfuscate_map THIS_FILE
//

ViewController ===> hTOUoUmUcEZUqhVHRrjrMUnYqbdqWByU
viewDidLoad ===> DLaNRaFbfmdTDuJCPFXrGhsWhoQyKLnO
sceneDidBecomeActive ===> SUANAnWpkyaIWlGUqwXitCoQSYeVilGe
AppDelegate ===> KftEWsJcctNEmGuvwZGPbusIxEFOVcIb
Deny_Debugger ===> lKEITOpOvLWCFgSCKZdUtpuqiwlvxSjx
Button_Emulator ===> akcVscrZFdBBYqYrcmhhyXAevNdXOKeG
```

这是对[加密的崩溃日志进行去混淆](https://github.com/rockbruno/swiftshield#-deobfuscating-encrypted-crash-logs)处理所必需的。

[SwiftShield 的Github](https://github.com/rockbruno/swiftshield/tree/master/ExampleProject)存储库中提供了另一个示例项目，可用于测试 SwiftShield 的执行。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#static-analysis)

尝试反汇编 IPA 中的 Mach-O 和“Frameworks”目录中包含的任何库文件（.dylib 或 .framework 文件），并执行静态分析。至少，应用程序的核心功能（即需要混淆的功能）不应轻易辨别。验证：

- 有意义的标识符，例如类名、方法名和变量名，已被丢弃。
- 二进制文件中的字符串资源和字符串是加密的。
- 与受保护功能相关的代码和数据被加密、打包或以其他方式隐藏。

要进行更详细的评估，您需要详细了解相关威胁和使用的混淆方法。

## 设备绑定 (MSTG-RESILIENCE-10)[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#device-binding-mstg-resilience-10)

### 概述[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#overview_6)

设备绑定的目的是阻止攻击者试图将应用程序及其状态从设备A复制到设备B并继续在设备B上执行该应用程序。在确定设备A被信任后，它可能拥有比设备更多的权限设备 B。当应用程序从设备 A 复制到设备 B 时，这种情况应该不会改变。

[从 iOS 7.0](https://developer.apple.com/library/content/releasenotes/General/RN-iOSSDK-7.0/index.html)开始，硬件标识符（例如 MAC 地址）是禁止使用的。将应用程序绑定到设备的方法是基于`identifierForVendor`，在 Keychain 中存储一些东西，或者使用谷歌的 InstanceID for iOS。有关更多详细信息，请参阅“[补救](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#remediation)”部分。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#static-analysis_1)

当源代码可用时，您可以查找一些不良的编码习惯，例如

- MAC 地址：有几种方法可以找到 MAC 地址。当您使用`CTL_NET`（网络子系统）或`NET_RT_IFLIST`（获取配置的接口）或格式化 mac-address 时，您会经常看到用于打印的格式化代码，例如`"%x:%x:%x:%x:%x:%x"`.
- 使用 UDID:`[[[UIDevice currentDevice] identifierForVendor] UUIDString];`和`UIDevice.current.identifierForVendor?.uuidString`Swift3。
- 任何基于钥匙串或文件系统的绑定，不受`SecAccessControlCreateFlags`或 保护并且不使用保护类，例如`kSecAttrAccessibleAlways`和`kSecAttrAccessibleAlwaysThisDeviceOnly`。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#dynamic-analysis)

有几种方法可以测试应用程序绑定。

#### 使用模拟器进行动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#dynamic-analysis-with-a-simulator)

当您想在模拟器中验证应用程序绑定时，请执行以下步骤：

1. 在模拟器上运行应用程序。
2. 确保您可以提高对应用程序实例的信任（例如，在应用程序中进行身份验证）。
3. 从模拟器中检索数据：
   - 因为模拟器使用 UUID 来标识自己，您可以通过创建调试点并`po NSHomeDirectory()`在该点上执行来更轻松地定位存储，这将揭示模拟器存储内容的位置。也可以`find ~/Library/Developer/CoreSimulator/Devices/ | grep <appname>`针对可疑的plist文件执行。
   - 转到给定命令输出指示的目录。
   - 复制找到的所有三个文件夹（Documents、Library、tmp）。
   - 复制钥匙串的内容。自 iOS 8 以来，这一直在`~/Library/Developer/CoreSimulator/Devices/<Simulator Device ID>/data/Library/Keychains`.
4. 在另一个模拟器上启动应用程序并按照步骤 3 中的描述找到其数据位置。
5. 在第二个模拟器上停止应用程序。使用在步骤 3 中复制的数据覆盖现有数据。
6. 你能继续处于认证状态吗？如果是这样，则绑定可能无法正常工作。

我们说绑定“可能”不起作用，因为在模拟器中并非所有内容都是独一无二的。

#### 使用两个越狱设备进行动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#dynamic-analysis-using-two-jailbroken-devices)

当您想要验证两个越狱设备的应用程序绑定时，请执行以下步骤：

1. 在您的越狱设备上运行该应用程序。
2. 确保您可以提高对应用程序实例的信任（例如，在应用程序中进行身份验证）。
3. 从越狱设备中检索数据：
   - 您可以通过 SSH 连接到您的设备并提取数据（与模拟器一样，使用调试或`find /private/var/mobile/Containers/Data/Application/ |grep <name of app>`）。该目录位于`/private/var/mobile/Containers/Data/Application/<Application uuid>`.
   - SSH 进入给定命令输出指示的目录或使用 SCP ( `scp <ipaddress>:/<folder_found_in_previous_step> targetfolder`) 复制文件夹及其数据。您也可以使用像 Filezilla 这样的 FTP 客户端。
   - 从存储在 中的钥匙串中检索数据，`/private/var/Keychains/keychain-2.db`您可以使用[Keychain-dumper](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#keychain-dumper)检索这些数据。
4. 在第二个越狱设备上安装应用程序。
5. 覆盖在步骤 3 中提取的应用程序数据。必须手动添加钥匙串数据。
6. 你能继续处于认证状态吗？如果是这样，则绑定可能无法正常工作。

### 整治[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#remediation)

在我们描述可用的标识符之前，让我们快速讨论一下如何将它们用于绑定。iOS中设备绑定的三种方式：

- 您可以使用`[[UIDevice currentDevice] identifierForVendor]`（在 Objective-C 中）、 `UIDevice.current.identifierForVendor?.uuidString`（在 Swift3 中）或`UIDevice.currentDevice().identifierForVendor?.UUIDString`（在 Swift2 中）。`identifierForVendor`如果您在安装同一供应商的其他应用程序后重新安装该应用程序，其值可能会有所不同，并且当您更新应用程序包的名称时，它可能会发生变化。因此最好将它与 Keychain 中的某些东西结合起来。
- 您可以在钥匙串中存储一些东西来识别应用程序的实例。为确保不备份此数据，请使用`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`（如果您想保护数据并正确执行密码或 Touch ID 要求）`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`，或`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`。
- 您可以使用 Google 及其适用于[iOS](https://developers.google.com/instance-id/guides/ios-implementation)的实例 ID 。

启用密码和/或 Touch ID 后，基于这些方法的任何方案都将更加安全，存储在钥匙串或文件系统中的材料受到保护类（例如`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`和`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`）的保护，并且`SecAccessControlCreateFlags`设置为`kSecAccessControlDevicePasscode`（对于密码） )、`kSecAccessControlUserPresence`（密码、面容 ID 或触控 ID）、`kSecAccessControlBiometryAny`（面容 ID 或触控 ID）或`kSecAccessControlBiometryCurrentSet`（面容 ID / 触控 ID：但仅限当前注册的生物识别技术）。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#references)

- [#geist] Dana Geist，Marat Nigmatullin。iOS 和 Android 上的越狱/Root 检测规避研究 - [https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/Jailbreak-Root-Detection-Evasion-Study-on-iOS-and-Android .pdf](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/Jailbreak-Root-Detection-Evasion-Study-on-iOS-and-Android.pdf)
- 简·塞雷丁斯基。对 1,300 个 AppStore 应用程序的安全审查（2020 年 4 月 5 日）- https://seredynski.com/articles/a-security-review-of-1300-appstore-applications.html

### OWASP MASVS[¶](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/#owasp-masvs)

- MSTG-RESILIENCE-1：“该应用程序通过提醒用户或终止该应用程序来检测并响应已破解或越狱设备的存在。”
- MSTG-RESILIENCE-2：“应用程序阻止调试和/或检测并响应附加的调试器。必须涵盖所有可用的调试协议。”
- MSTG-RESILIENCE-3：“该应用程序检测并响应篡改其自身沙箱中的可执行文件和关键数据。”
- MSTG-RESILIENCE-4：“该应用程序检测并响应设备上广泛使用的逆向工程工具和框架的存在。”
- MSTG-RESILIENCE-5：“应用程序检测并响应在模拟器中运行。”
- MSTG-RESILIENCE-9：“混淆应用于程序化防御，这反过来又通过动态分析阻碍了去混淆。”
- MSTG-RESILIENCE-10：“该应用程序使用从设备唯一的多个属性派生的设备指纹来实现‘设备绑定’功能。”
- MSTG-RESILIENCE-11：“属于应用程序的所有可执行文件和库都在文件级别加密和/或可执行文件中的重要代码和数据段被加密或打包。简单的静态分析不会揭示重要的代码或数据。 “
