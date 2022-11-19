# iOS 基本安全测试[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#ios-basic-security-testing)

在上一章中，我们概述了 iOS 平台并描述了其应用程序的结构。在本章中，我们将讨论如何设置安全测试环境，并介绍可用于测试 iOS 应用程序是否存在安全漏洞的基本流程和技术。这些基本过程是以下章节中概述的测试用例的基础。

## iOS 测试设置[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#ios-testing-setup)

尽管您可以使用 Linux 或 Windows 主机进行测试，但您会发现许多任务在这些平台上很难或无法完成。此外，Xcode 开发环境和 iOS SDK 仅适用于 macOS。这意味着您肯定希望在 macOS 上工作以进行源代码分析和调试（这也使黑盒测试更加容易）。

### 主机设备[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#host-device)

以下是最基本的 iOS 应用程序测试设置：

- 最好是具有管理员权限的 macOS 主机
- [安装了Xcode](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#xcode)和[Xcode 命令行工具](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#xcode-command-line-tools)。
- 允许客户端到客户端流量的 Wi-Fi 网络。
- 至少一台越狱的 iOS 设备（所需的 iOS 版本）。
- [Burp Suite](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#burp-suite)或其他拦截代理工具。

### 检测装置[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#testing-device)

#### 获取 iOS 设备的 UDID[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#getting-the-udid-of-an-ios-device)

UDID 是一个 40 位的唯一字母和数字序列，用于识别 iOS 设备。您可以在 macOS Catalina 上的 Finder 应用程序中找到您的 iOS 设备的 UDID，因为 iTunes 在 Catalina 中不再可用。打开 Finder 并在边栏中选择已连接的 iOS 设备。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/finder_ipad_view.png)

单击包含型号、存储容量和电池信息的文本，将显示序列号、UDID 和型号：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/finder_unveil_udid.png)

您可以通过右键单击它来复制 UDID。

当设备通过 USB 连接时，也可以通过 macOS 上的各种命令行工具获取 UDID：

- 通过使用[I/O Registry Explorer](https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/TheRegistry/TheRegistry.html)工具`ioreg`：

  ```
  $ ioreg -p IOUSB -l | grep "USB Serial"
  |         "USB Serial Number" = "9e8ada44246cee813e2f8c1407520bf2f84849ec"
  ```

- 通过使用[ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller)（在 Linux 上也可用）：

  ```
  $ brew install ideviceinstaller
  $ idevice_id -l
  316f01bd160932d2bf2f95f1f142bc29b1c62dbc
  ```

- 通过使用 system_profiler：

  ```
  $ system_profiler SPUSBDataType | sed -n -e '/iPad/,/Serial/p;/iPhone/,/Serial/p;/iPod/,/Serial/p' | grep "Serial Number:"
  2019-09-08 10:18:03.920 system_profiler[13251:1050356] SPUSBDevice: IOCreatePlugInInterfaceForService failed 0xe00002be
              Serial Number: 64655621de6ef5e56a874d63f1e1bdd14f7103b1
  ```

- 通过使用仪器：

  ```
  instruments -s devices
  ```

#### 在真实设备上测试（越狱）[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#testing-on-a-real-device-jailbroken)

你应该有一个越狱的 iPhone 或 iPad 来运行测试。这些设备允许根访问和工具安装，使安全测试过程更加直接。如果您无法访问越狱设备，您可以应用本章后面描述的变通方法，但要为更困难的体验做好准备。

#### 在 iOS 模拟器上测试[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#testing-on-the-ios-simulator)

与完全模拟实际 Android 设备硬件的 Android 模拟器不同，iOS SDK 模拟器提供了更高级别的 iOS 设备*模拟*。最重要的是，模拟器二进制文件被编译为 x86 代码而不是 ARM 代码。为真实设备编译的应用程序无法运行，使得模拟器无法用于黑盒分析和逆向工程。

#### 在模拟器上测试[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#testing-on-an-emulator)

[Corellium](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#corellium)是唯一公开可用的 iOS 模拟器。它是一种企业 SaaS 解决方案，采用按用户许可模式，不提供社区许可。

#### 获得特权访问[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#getting-privileged-access)

iOS 越狱通常与 Android 越狱相提并论，但过程实际上大不相同。为了解释差异，我们将首先回顾一下 Android 上“root”和“刷机”的概念。

- **Root**：这通常涉及`su`在系统上安装二进制文件或用已Root的自定义 ROM 替换整个系统。只要可以访问引导加载程序，就不需要利用漏洞来获得根访问权限。
- **闪烁自定义 ROM**：这允许您在解锁引导加载程序后替换设备上运行的操作系统。引导加载程序可能需要利用漏洞来解锁它。

在 iOS 设备上，刷入自定义 ROM 是不可能的，因为 iOS 引导加载程序只允许引导和刷入 Apple 签名的映像。这就是为什么如果没有 Apple 签名，即使官方 iOS 映像也无法安装，并且只有在以前的 iOS 版本仍然签名的情况下，iOS 才能降级。

越狱的目的是禁用 iOS 保护（特别是 Apple 的代码签名机制），以便可以在设备上运行任意未签名的代码（例如，自定义代码或从替代应用程序商店（如[Cydia](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#cydia)或[Sileo](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#sileo) ）下载的代码）。“越狱”这个词是对自动禁用过程的多合一工具的通俗引用。

为给定版本的 iOS 开发越狱并不容易。作为一名安全测试人员，您很可能希望使用公开可用的越狱工具。尽管如此，我们还是建议您研究用于越狱各种版本的 iOS 的技术——您会遇到许多有趣的漏洞利用，并了解很多关于操作系统内部的知识。例如，适用于 iOS 9.x 的 Pangu9[至少利用了五个漏洞](https://www.theiphonewiki.com/wiki/Jailbreak_Exploits)，包括释放后使用内核错误 (CVE-2015-6794) 和照片应用程序中的任意文件系统访问漏洞 (CVE-2015-7037)。

某些应用程序会尝试检测运行它们的 iOS 设备是否已越狱。这是因为越狱会停用 iOS 的一些默认安全机制。然而，有几种方法可以绕过这些检测，我们将在[“iOS 反逆向防御”](https://mas.owasp.org/MASTG/iOS/0x06j-Testing-Resiliency-Against-Reverse-Engineering/)一章中介绍它们。

##### 越狱的好处[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#benefits-of-jailbreaking)

最终用户经常越狱他们的设备以调整 iOS 系统的外观、添加新功能以及从非官方应用程序商店安装第三方应用程序。然而，对于安全测试人员来说，越狱 iOS 设备还有更多好处。它们包括但不限于以下内容：

- 对文件系统的根访问权限。
- 可以执行未经 Apple 签名的应用程序（其中包括许多安全工具）。
- 不受限制的调试和动态分析。
- 访问 Objective-C 或 Swift Runtime(运行时)。

##### 越狱类型[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#jailbreak-types)

有*tethered*、*semi-tethered*、*semi-untethered*和*untethered*越狱。

- 系留越狱不会通过重新启动持续存在，因此重新应用越狱需要在每次重新启动期间将设备连接（系留）到计算机。如果未连接计算机，设备可能根本不会重新启动。
- 除非设备在重启期间连接到计算机，否则无法重新应用半系留越狱。该设备还可以自行启动到非越狱模式。
- 半自由越狱允许设备自行启动，但不会自动应用用于禁用代码签名的内核补丁（或用户空间修改）。用户必须通过启动应用程序或访问网站（不需要连接到计算机，因此称为不受限制）来重新越狱设备。
- 不受限制的越狱是最终用户最流行的选择，因为它们只需要应用一次，之后设备将被永久越狱。

##### 注意事项和注意事项[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#caveats-and-considerations)

随着 Apple 不断加强其操作系统，为 iOS 开发越狱变得越来越复杂。每当 Apple 发现漏洞时，都会对其进行修补，并向所有用户推送系统更新。由于无法降级到特定版本的 iOS，并且由于 Apple 只允许您更新到最新的 iOS 版本，因此让设备运行可以越狱的 iOS 版本是一个挑战。有些漏洞无法通过软件修补，例如影响 A12 之前所有 CPU 的 BootROM的[checkm8 漏洞利用。](https://www.theiphonewiki.com/wiki/Checkm8_Exploit)

如果您有用于安全测试的越狱设备，请保持原样，除非您 100% 确定升级到最新的 iOS 版本后可以重新越狱。考虑获得一个（或多个）备用设备（每个主要 iOS 版本都会更新）并等待公开发布越狱。一旦公开发布越狱，Apple 通常会很快发布补丁，因此您只有几天时间降级（如果它仍然由 Apple 签名）到受影响的 iOS 版本并应用越狱。

iOS 升级基于挑战-响应过程（结果生成所谓的 SHSH blob）。仅当对质询的响应由 Apple 签名时，设备才会允许安装操作系统。这就是研究人员所说的“签名窗口”，这也是您不能简单地存储下载的 OTA 固件包并在需要时将其加载到设备上的原因。在较小的 iOS 升级期间，两个版本可能都由 Apple 签名（最新版本和以前的 iOS 版本）。这是您可以降级 iOS 设备的唯一情况。您可以检查当前的签名窗口并从[IPSW 下载网站](https://ipsw.me/)下载 OTA 固件。

对于某些设备和 iOS 版本，如果在签名窗口处于活动状态时收集了该设备的 SHSH blob，则可以降级到旧版本。有关这方面的更多信息，请参阅[cfw iOS 指南 - 保存 Blob](https://ios.cfw.guide/saving-blobs/)

##### 使用哪种越狱工具[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#which-jailbreaking-tool-to-use)

不同的 iOS 版本需要不同的越狱技术。[确定公共越狱是否适用于您的 iOS 版本](https://appledb.dev/)。谨防假冒工具和间谍软件，它们通常隐藏在与越狱组/作者姓名相似的域名后面。

iOS 越狱场景发展如此迅速，以至于很难提供最新的说明。但是，我们可以为您指出一些目前可靠的来源。

- [苹果数据库](https://appledb.dev/)
- [The iPhone Wiki](https://www.theiphonewiki.com/)
- [Redmond Pie](https://www.redmondpie.com/)
- [越狱](https://www.reddit.com/r/jailbreak/)

> 请注意，您对设备所做的任何修改均由您自行承担风险。虽然越狱通常是安全的，但也可能出现问题，最终可能导致设备变砖。除您本人外，任何其他方均不对任何损害负责。

## 基本测试操作[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#basic-testing-operations)

### 访问设备Shell[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#accessing-the-device-shell)

测试应用程序时最常做的事情之一是访问设备Shell。在本节中，我们将了解如何使用/不使用 USB 电缆从主机远程访问 iOS shell，以及如何从设备本身本地访问 iOS shell。

#### 远程Shell[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#remote-shell)

与您可以使用 adb 工具轻松访问设备 shell 的 Android 相比，在 iOS 上您只能选择通过 SSH 访问远程 shell。这也意味着您的 iOS 设备必须越狱才能从主机连接到其Shell。对于本节，我们假设您已正确越狱您的设备并安装了[Cydia](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#cydia)（请参见下面的屏幕截图）或[Sileo](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#sileo)。在本指南的其余部分，我们将参考 Cydia，但 Sileo 中应该可以使用相同的软件包。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/cydia.png)

为了启用 SSH 访问您的 iOS 设备，您可以安装 OpenSSH 包。安装后，确保将两台设备连接到同一个 Wi-Fi 网络并记下设备 IP 地址，您可以在**设置 -> Wi-Fi**菜单中找到该地址，然后点击一次您所在网络的信息图标'连接到。

您现在可以通过运行访问远程设备的 shell `ssh root@<device_ip_address>`，这将使您以 root 用户身份登录：

```
$ ssh root@192.168.197.234
root@192.168.197.234's password:
iPhone:~ root#
```

按 Control + D 或键入`exit`退出。

通过 SSH 访问您的 iOS 设备时，请考虑以下事项：

- 默认用户是`root`和`mobile`。
- 两者的默认密码都是`alpine`。

> 请记住更改两个用户的默认密码，`root`因为`mobile`同一网络上的任何人都可以找到您设备的 IP 地址并通过众所周知的默认密码进行连接，这将使他们获得对您设备的根访问权限。

如果您忘记密码并想将其重置为默认密码`alpine`：

1. 在越狱的 iOS 设备上编辑文件`/private/etc/master.password`（使用设备上的 shell，如下所示）
2. 查找行：

```
 root:xxxxxxxxx:0:0::0:0:System Administrator:/var/root:/bin/sh
 mobile:xxxxxxxxx:501:501::0:0:Mobile User:/var/mobile:/bin/sh
```

1. 更改`xxxxxxxxx`为`/smx7MYTQIi2M`（这是散列密码`alpine`）
2. 保存并退出

##### 通过 SSH OVER USB 连接到设备[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#connect-to-a-device-via-ssh-over-usb)

在真正的黑盒测试中，可能无法使用可靠的 Wi-Fi 连接。在这种情况下，您可以使用[usbmuxd](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#usbmuxd)通过 USB 连接到您设备的 SSH 服务器。

通过安装和启动[iproxy](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#iproxy)将 macOS 连接到 iOS 设备：

```
$ brew install libimobiledevice
$ iproxy 2222 22
waiting for connection
```

`22`上面的命令将iOS 设备上的端口映射到`2222`本地主机上的端口。如果您不想每次通过 USB 连接 SSH 时都运行二进制文件，您也可以[让 iproxy 在后台自动运行。](https://iphonedevwiki.net/index.php/SSH_Over_USB)

在新的终端窗口中使用以下命令，您可以连接到设备：

```
$ ssh -p 2222 root@localhost
root@localhost's password:
iPhone:~ root#
```

> 关于 iDevice USB 的小提示：在 iOS 设备上，处于锁定状态 1 小时后，您将无法再进行数据连接，除非您由于 iOS 11.4.1 引入的 USB 限制模式而再次解锁它

#### 设备上的Shell应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#on-device-shell-app)

虽然与远程 shell 相比，通常使用设备上的 shell（终端仿真器）可能非常乏味，但事实证明它可以方便地进行调试，例如在出现网络问题或检查某些配置时。例如，您可以为此目的通过 Cydia 安装[NewTerm 2](https://repo.chariz.io/package/ws.hbang.newterm2/)（在撰写本文时它支持 iOS 6.0 到 12.1.2）。

此外，还有一些越狱*出于安全原因*明确禁用传入的 SSH 。在这些情况下，拥有一个设备上的 shell 应用程序非常方便，您可以使用它首先使用反向 shell 通过 SSH 从设备退出，然后从您的主机连接到它。

可以通过运行命令来通过 SSH 打开反向 shell `ssh -R <remote_port>:localhost:22 <username>@<host_computer_ip>`。

在设备上的 shell 应用程序上运行以下命令，并在询问时输入`mstg`主机用户的密码：

```
ssh -R 2222:localhost:22 mstg@192.168.197.235
```

在您的主机上运行以下命令，并在询问时输入`root`iOS 设备用户的密码：

```
ssh -p 2222 root@localhost
```

### 主机设备数据传输[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#host-device-data-transfer)

在各种情况下，您可能需要将数据从 iOS 设备或应用程序数据沙箱传输到主机，反之亦然。以下部分将向您展示实现该目标的不同方法。

#### 通过 SSH 和 SCP 复制应用程序数据文件[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#copying-app-data-files-via-ssh-and-scp)

正如我们现在所知，我们应用程序中的文件存储在 Data 目录中。您现在可以简单地存档 Data 目录`tar`并使用以下命令将其从设备中拉出`scp`：

```
iPhone:~ root# tar czvf /tmp/data.tgz /private/var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693
iPhone:~ root# exit
$ scp -P 2222 root@localhost:/tmp/data.tgz .
```

#### 百香果[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#passionfruit)

启动[Passionfruit](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#passionfruit)后，您可以选择在测试范围内的应用程序。有各种可用的功能，其中一个称为“文件”。选择它时，您将获得应用程序沙箱目录的列表。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_data_dir.png)

在目录中导航并选择文件时，将出现一个弹出窗口并以十六进制或文本形式显示数据。关闭此弹出窗口时，您可以为该文件提供多种选项，包括：

- 文本查看器
- SQLite 查看器
- 图像查看器
- Plist查看器
- 下载

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_file_download.png)

#### objection[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#objection)

当您开始objection时，您会在 Bundle 目录中找到提示。

```
org.owasp.MSTG on (iPhone: 10.3.3) [usb] # pwd print
Current directory: /var/containers/Bundle/Application/DABF849D-493E-464C-B66B-B8B6C53A4E76/org.owasp.MSTG.app
```

使用`env`命令获取应用程序的目录并导航到 Documents 目录。

```
org.owasp.MSTG on (iPhone: 10.3.3) [usb] # cd /var/mobile/Containers/Data/Application/72C7AAFB-1D75-4FBA-9D83-D8B4A2D44133/Documents
/var/mobile/Containers/Data/Application/72C7AAFB-1D75-4FBA-9D83-D8B4A2D44133/Documents
```

使用该命令`file download <filename>`，您可以将文件从 iOS 设备下载到您的主机，然后可以对其进行分析。

```
org.owasp.MSTG on (iPhone: 10.3.3) [usb] # file download .com.apple.mobile_container_manager.metadata.plist
Downloading /var/mobile/Containers/Data/Application/72C7AAFB-1D75-4FBA-9D83-D8B4A2D44133/.com.apple.mobile_container_manager.metadata.plist to .com.apple.mobile_container_manager.metadata.plist
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /var/mobile/Containers/Data/Application/72C7AAFB-1D75-4FBA-9D83-D8B4A2D44133/.com.apple.mobile_container_manager.metadata.plist to .com.apple.mobile_container_manager.metadata.plist
```

您还可以将文件上传到 iOS 设备`file upload <local_file_path>`。

### 获取和提取应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#obtaining-and-extracting-apps)

#### 从 OTA 分发链接获取 IPA 文件[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#getting-the-ipa-file-from-an-ota-distribution-link)

在开发过程中，应用程序有时会通过无线 (OTA) 分发提供给测试人员。在这种情况下，您会收到一个 itms-services 链接，如下所示：

```
itms-services://?action=download-manifest&url=https://s3-ap-southeast-1.amazonaws.com/test-uat/manifest.plist
```

您可以使用[ITMS 服务资产下载](https://www.npmjs.com/package/itms-services)器工具从 OTA 分发 URL 下载 IPA。通过 npm 安装它：

```
npm install -g itms-services
```

使用以下命令在本地保存 IPA 文件：

```
# itms-services -u "itms-services://?action=download-manifest&url=https://s3-ap-southeast-1.amazonaws.com/test-uat/manifest.plist" -o - > out.ipa
```

#### 获取应用程序二进制文件[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#acquiring-the-app-binary)

1. 来自 IPA：

如果你有 IPA（可能包括一个已经解密的应用程序二进制文件），解压它，你就可以开始了。应用程序二进制文件位于主包目录 (.app) 中，例如`Payload/Telegram X.app/Telegram X`. 有关提取属性列表的详细信息，请参阅以下小节。

```
> On macOS's Finder, .app directories are opened by right-clicking them and selecting "Show Package Content". On the terminal you can just `cd` into them.
```

1. 从越狱设备：

   如果您没有原始 IPA，那么您需要一个越狱设备，您将在其中安装该应用程序（例如通过 App Store）。安装后，您需要从内存中提取应用二进制文件并重建 IPA 文件。由于 DRM，应用程序二进制文件在存储在 iOS 设备上时会被加密，因此简单地从 Bundle 中提取它（通过 SSH 或 Objection）不足以对其进行逆向工程。

下面显示了在 Telegram 应用程序上运行[class-dump](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#class-dump)的输出，它是直接从 iPhone 的安装目录中拉取的：

```
$ class-dump Telegram
//
//     Generated by class-dump 3.5 (64 bit) (Debug version compiled Jun  9 2015 22:53:21).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2014 by Steve Nygard.
//

#pragma mark -

//
// File: Telegram
// UUID: EAF90234-1538-38CF-85B2-91A84068E904
//
//                           Arch: arm64
//                 Source version: 0.0.0.0.0
//            Minimum iOS version: 8.0.0
//                    SDK version: 12.1.0
//
// Objective-C Garbage Collection: Unsupported
//
//                       Run path: @executable_path/Frameworks
//                               = /Frameworks
//         This file is encrypted:
//                                   cryptid: 0x00000001
//                                  cryptoff: 0x00004000
//                                 cryptsize: 0x000fc000
//
```

为了检索未加密的版本，您可以使用[frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump)（所有 iOS 版本）或[Clutch](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#clutch)（仅限 iOS 11；对于 iOS 12 及更高版本，需要补丁）等工具。当应用程序在设备上Runtime(运行时)，两者都会从内存中提取未加密的版本。Clutch 和 frida-ios-dump 的稳定性可能会因您的 iOS 版本和越狱方法而异，因此使用多种方式提取二进制文件很有用。

> **重要说明：**在美国，数字千年版权法 17 USC 1201 或 DMCA 规定规避某些类型的 DRM 是非法的并且可以采取行动。但是，DMCA 也提供豁免，例如某些类型的安全研究。合格的律师可以帮助您确定您的研究是否符合 DMCA 豁免条件。（来源：[Corellium](https://support.corellium.com/en/articles/6181345-testing-third-party-ios-apps)）

##### 使用离合器[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#using-clutch)

按照 Clutch GitHub 页面上的说明构建[Clutch](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#clutch)，并通过 将其推送到 iOS 设备`scp`。`-i`使用标志运行 Clutch以列出所有已安装的应用程序：

```
root# ./Clutch -i
2019-06-04 20:16:57.807 Clutch[2449:440427] command: Prints installed applications
Installed apps:
...
5:   Telegram Messenger <ph.telegra.Telegraph>
...
```

获得包标识符后，您可以使用 Clutch 创建 IPA：

```
root# ./Clutch -d ph.telegra.Telegraph
2019-06-04 20:19:28.460 Clutch[2450:440574] command: Dump specified bundleID into .ipa file
ph.telegra.Telegraph contains watchOS 2 compatible application. It's not possible to dump watchOS 2 apps with Clutch (null) at this moment.
Zipping Telegram.app
2019-06-04 20:19:29.825 clutch[2465:440618] command: Only dump binary files from specified bundleID
...
Successfully dumped framework TelegramUI!
Zipping WebP.framework
Zipping NotificationContent.appex
Zipping NotificationService.appex
Zipping Share.appex
Zipping SiriIntents.appex
Zipping Widget.appex
DONE: /private/var/mobile/Documents/Dumped/ph.telegra.Telegraph-iOS9.0-(Clutch-(null)).ipa
Finished dumping ph.telegra.Telegraph in 20.5 seconds
```

将 IPA 文件复制到主机系统并解压缩后，您可以看到 Telegram 应用程序二进制文件现在可以通过[class-dump](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#class-dump)进行解析，表明它不再加密：

```
$ class-dump Telegram
...
//
//     Generated by class-dump 3.5 (64 bit) (Debug version compiled Jun  9 2015 22:53:21).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2014 by Steve Nygard.
//

#pragma mark Blocks

typedef void (^CDUnknownBlockType)(void); // return type and parameters are unknown

#pragma mark Named Structures

struct CGPoint {
    double _field1;
    double _field2;
};
...
```

注意：在iOS 12上使用[Clutch](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#clutch)时，请查看[Clutch Github issue 228](https://github.com/KJCracks/Clutch/issues/228)

##### 使用 FRIDA-IOS-DUMP[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#using-frida-ios-dump)

首先，确保[Frida-ios-dump](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#frida-ios-dump) `dump.py`中的配置设置为使用[iproxy](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#iproxy)时端口为 2222 的本地主机，或者设置为要从中转储二进制文件的设备的实际 IP 地址和端口。接下来，将默认用户名 ( `User = 'root'`) 和密码 ( `Password = 'alpine'`)`dump.py`更改为您使用的用户名。

现在您可以安全地使用该工具来枚举已安装的应用程序：

```
$ python dump.py -l
 PID  Name             Identifier
----  ---------------  -------------------------------------
 860  Cydia            com.saurik.Cydia
1130  Settings         com.apple.Preferences
 685  Mail             com.apple.mobilemail
 834  Telegram         ph.telegra.Telegraph
   -  Stocks           com.apple.stocks
   ...
```

您可以转储列出的二进制文件之一：

```
$ python dump.py ph.telegra.Telegraph

Start the target app ph.telegra.Telegraph
Dumping Telegram to /var/folders/qw/gz47_8_n6xx1c_lwq7pq5k040000gn/T
[frida-ios-dump]: HockeySDK.framework has been loaded.
[frida-ios-dump]: Load Postbox.framework success.
[frida-ios-dump]: libswiftContacts.dylib has been dlopen.
...
start dump /private/var/containers/Bundle/Application/14002D30-B113-4FDF-BD25-1BF740383149/Telegram.app/Frameworks/libswiftsimd.dylib
libswiftsimd.dylib.fid: 100%|██████████| 343k/343k [00:00<00:00, 1.54MB/s]
start dump /private/var/containers/Bundle/Application/14002D30-B113-4FDF-BD25-1BF740383149/Telegram.app/Frameworks/libswiftCoreData.dylib
libswiftCoreData.dylib.fid: 100%|██████████| 82.5k/82.5k [00:00<00:00, 477kB/s]
5.m4a: 80.9MB [00:14, 5.85MB/s]
0.00B [00:00, ?B/s]Generating "Telegram.ipa"
```

在此之后，该`Telegram.ipa`文件将在您的当前目录中创建。您可以通过删除应用程序并重新安装它（例如使用[ios-deploy](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#ios-deploy) `ios-deploy -b Telegram.ipa`）来验证转储是否成功。请注意，这仅适用于越狱设备，否则签名将无效。

### 重新打包应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#repackaging-apps)

如果您需要在未越狱的设备上进行测试，您应该学习如何重新打包应用程序以在其上启用动态测试。

使用装有 macOS 的计算机执行反对 Wiki中文章[“修补 iOS 应用程序”中指示的所有步骤。](https://github.com/sensepost/objection/wiki/Patching-iOS-Applications)完成后，您将能够通过调用反对命令来修补 IPA：

```
objection patchipa --source my-app.ipa --codesign-signature 0C2E8200Dxxxx
```

最后，应用程序需要安装（旁加载）并在启用调试通信的情况下运行。执行来自反对 Wiki的文章[“运行修补的 iOS 应用程序”中的步骤（使用 ios-deploy）。](https://github.com/sensepost/objection/wiki/Running-Patched-iOS-Applications)

```
ios-deploy --bundle Payload/my-app.app -W -d
```

其他安装方式请参考[“安装应用” 。](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#installing-apps)其中一些不需要您拥有 macOS。

> 这种重新打包方法足以满足大多数用例。更高级的重新打包，请参考[“iOS篡改和逆向工程——修补、重新打包和重新签名”](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#patching-repackaging-and-re-signing)。

### 安装应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#installing-apps)

当您在不使用 Apple 的 App Store 的情况下安装应用程序时，这称为侧载。有多种侧载方式，如下所述。在 iOS 设备上，实际的安装过程由 installd 守护进程处理，它将解压并安装应用程序。要集成应用程序服务或安装在 iOS 设备上，所有应用程序都必须使用 Apple 颁发的证书进行签名。这意味着只有在代码签名验证成功后才能安装应用程序。但是，在越狱手机上，您可以使用[AppSync绕过此安全功能](http://repo.hackyouriphone.org/appsyncunified)，一个在 Cydia 商店中可用的软件包。它包含许多有用的应用程序，这些应用程序利用越狱提供的根权限来执行高级功能。AppSync 是一个补丁安装的调整，允许安装假签名的 IPA 包。

将 IPA 包安装到 iOS 设备上存在不同的方法，下面将对其进行详细描述。

> 请注意，macOS Catalina 不再提供 iTunes。如果您使用的是旧版本的 macOS，iTunes 仍然可用，但从 iTunes 12.7 开始无法安装应用程序。

#### Cydia 冲击器[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#cydia-impactor)

[Cydia Impactor](http://www.cydiaimpactor.com/)最初是为 iPhone 越狱而创建的，但已被重写为通过侧载将 IPA 包签名并安装到 iOS 设备（甚至是 APK 文件到 Android 设备）。Cydia Impactor 适用于 Windows、macOS 和 Linux。yalujailbreak.net[上提供了分步指南和故障排除步骤](https://yalujailbreak.net/how-to-use-cydia-impactor/)。

#### 自由移动设备[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#libimobiledevice)

在 Linux 和 macOS 上，您可以选择使用[libimobiledevice](https://www.libimobiledevice.org/)，这是一个跨平台软件协议库和一组用于与 iOS 设备进行Native通信的工具。这允许您通过执行 ideviceinstaller 通过 USB 连接安装应用程序。该连接是通过 USB 多路复用守护程序[usbmuxd](https://www.theiphonewiki.com/wiki/Usbmux)实现的，它提供了一个基于 USB 的 TCP 隧道。

libimobiledevice 的包将在您的 Linux 包管理器中可用。在 macOS 上，您可以通过 brew 安装 libimobiledevice：

```
brew install libimobiledevice
brew install ideviceinstaller
```

安装后，您可以使用几个新的命令行工具，例如`ideviceinfo`,`ideviceinstaller`或`idevicedebug`.

```
# The following command will show detailed information about the iOS device connected via USB.
$ ideviceinfo
# The following command will install the IPA to your iOS device.
$ ideviceinstaller -i iGoat-Swift_v1.0-frida-codesigned.ipa
...
Install: Complete
# The following command will start the app in debug mode, by providing the bundle name. The bundle name can be found in the previous command after "Installing".
$ idevicedebug -d run OWASP.iGoat-Swift
```

#### ipain安装程序[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#ipainstaller)

IPA 也可以通过命令行使用[ipainstaller](https://github.com/autopear/ipainstaller)直接安装在 iOS 设备上。将文件复制到设备后，例如通过 scp，您可以使用 IPA 的文件名执行 ipainstaller：

```
ipainstaller App_name.ipa
```

#### ios部署[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#ios-deploy)

在 macOS 上，您还可以使用[ios-deploy](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#ios-deploy)工具从命令行安装 iOS 应用程序。你需要解压缩你的 IPA，因为 ios-deploy 使用应用程序包来安装应用程序。

```
unzip Name.ipa
ios-deploy --bundle 'Payload/Name.app' -W -d -v
```

在iOS设备上安装好app后，只需添加`-m`flag即可启动，直接开始调试，无需再次安装app。

```
ios-deploy --bundle 'Payload/Name.app' -W -d -v -m
```

#### Xcode[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#xcode)

也可以通过执行以下步骤使用 Xcode IDE 安装 iOS 应用程序：

1. 启动 Xcode
2. 选择**窗口/设备和模拟器**
3. 选择已连接的 iOS 设备，然后单击**Installed Apps中的****+**号。

#### 允许在非 iPad 设备上安装应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#allow-application-installation-on-a-non-ipad-device)

有时，应用程序可能需要在 iPad 设备上使用。如果您只有 iPhone 或 iPod touch 设备，那么您可以强制应用程序接受在这些类型的设备上安装和使用。您可以通过在**Info.plist**文件中将属性**UIDeviceFamily**的值更改为值**1来执行此操作。**

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>

  <key>UIDeviceFamily</key>
  <array>
    <integer>1</integer>
  </array>

</dict>
</plist>  
```

请务必注意，更改此值会破坏 IPA 文件的原始签名，因此您需要在更新后重新签署 IPA，以便将其安装在未禁用签名验证的设备上。

如果应用程序需要特定于现代 iPad 的功能，而您的 iPhone 或 iPod 稍旧一些，则此绕过可能不起作用。

可以在 Apple Developer 文档中找到属性[UIDeviceFamily](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/uid/TP40009252-SW11)的可能值。

### 信息收集[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#information-gathering)

分析应用程序的一个基本步骤是信息收集。这可以通过检查主机上的应用程序包或通过访问设备上的应用程序数据来远程完成。您将在后续章节中找到更多高级技术，但目前我们将重点关注基础知识：获取所有已安装应用程序的列表、浏览应用程序包以及访问设备本身的应用程序数据目录。这应该让您对应用程序的全部内容有一些了解，甚至不必对其进行逆向工程或执行更高级的分析。我们将回答以下问题：

- 包中包含哪些文件？
- 该应用程序使用哪些框架？
- 该应用程序需要哪些功能？
- 应用程序向用户请求哪些权限以及出于什么原因？
- 该应用程序是否允许任何不安全的连接？
- 该应用程序在安装时是否会创建任何新文件？

#### 列出已安装的应用程序[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#listing-installed-apps)

当定位安装在设备上的应用程序时，您首先必须找出要分析的应用程序的正确包标识符。您可以使用`frida-ps -Uai`获取连接的 USB 设备 ( ) 上`-a`当前安装 ( ) 的所有应用程序 ( )：`-i``-U`

```
$ frida-ps -Uai
 PID  Name                 Identifier
----  -------------------  -----------------------------------------
6847  Calendar             com.apple.mobilecal
6815  Mail                 com.apple.mobilemail
   -  App Store            com.apple.AppStore
   -  Apple Store          com.apple.store.Jolly
   -  Calculator           com.apple.calculator
   -  Camera               com.apple.camera
   -  iGoat-Swift          OWASP.iGoat-Swift
```

它还显示其中哪些当前正在运行。记下“标识符”（捆绑包标识符）和 PID（如果有的话），因为之后您将需要它们。

您也可以直接打开百香果，在选择您的 iOS 设备后，您将获得已安装应用程序的列表。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_installed_apps.png)

#### 探索应用程序包[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#exploring-the-app-package)

一旦您收集了您想要作为目标的应用程序的包名称，您将要开始收集有关它的信息。[首先，按照基本测试操作 - 获取和提取应用程序](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#obtaining-and-extracting-apps)中的说明检索 IPA 。

`unzip`您可以使用标准或任何其他 ZIP 实用程序解压缩 IPA 。在里面您会发现一个`Payload`文件夹，其中包含所谓的应用程序包 (.app)。以下是以下输出中的示例，请注意，为了更好的可读性和概述，它被截断了：

```
$ ls -1 Payload/iGoat-Swift.app
rutger.html
mansi.html
splash.html
about.html

LICENSE.txt
Sentinel.txt
README.txt

URLSchemeAttackExerciseVC.nib
CutAndPasteExerciseVC.nib
RandomKeyGenerationExerciseVC.nib
KeychainExerciseVC.nib
CoreData.momd
archived-expanded-entitlements.xcent
SVProgressHUD.bundle

Base.lproj
Assets.car
PkgInfo
_CodeSignature
AppIcon60x60@3x.png

Frameworks

embedded.mobileprovision

Credentials.plist
Assets.plist
Info.plist

iGoat-Swift
```

最相关的项目是：

- `Info.plist`包含应用程序的配置信息，例如它的包 ID、版本号和显示名称。
- `_CodeSignature/`包含一个 plist 文件，该文件对捆绑包中的所有文件进行签名。
- `Frameworks/`包含应用程序Native库(NATIVE LIBRARIES)作为 .dylib 或 .framework 文件。
- `PlugIns/`可能包含应用扩展作为 .appex 文件（示例中不存在）。
- [iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)是包含应用程序代码的应用程序二进制文件。它的名称与捆绑包的名称相同，只是减去 .app 扩展名。
- 各种资源，例如图像/图标、`*.nib`文件（存储 iOS 应用程序的用户界面）、本地化内容 ( `<language>.lproj`)、文本文件、音频文件等。

##### INFO.PLIST 文件[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#the-infoplist-file)

信息属性列表或`Info.plist`（按惯例命名）是 iOS 应用程序的主要信息来源。它由一个结构化文件组成，其中包含描述应用程序基本配置信息的键值对。实际上，所有捆绑的可执行文件（应用程序扩展、框架和应用程序）都应该有一个`Info.plist`文件。[您可以在Apple Developer Documentation](https://developer.apple.com/documentation/bundleresources/information_property_list?language=objc)中找到所有可能的密钥。

该文件可能采用 XML 或二进制格式 (bplist)。您可以使用一个简单的命令将其转换为 XML 格式：

- 在 macOS 上`plutil`，这是 macOS 10.2 及以上版本原生自带的工具（目前没有官方在线文档）：

```
plutil -convert xml1 Info.plist
```

- 在 Linux 上：

```
apt install libplist-utils
plistutil -i Info.plist -o Info_xml.plist
```

这是一些信息和相应关键字的非详尽列表，您可以`Info.plist`通过检查文件或使用以下方式轻松地在文件中搜索`grep -i <keyword> Info.plist`：

- 应用程序权限目的字符串：（`UsageDescription`请参阅“ [iOS 平台 API](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/) ”）
- 自定义 URL 方案：（`CFBundleURLTypes`参见“ [iOS 平台 API](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/) ”）
- 导出/导入的*自定义文档类型*：`UTExportedTypeDeclarations`/ `UTImportedTypeDeclarations`（参见“ [iOS 平台 API](https://mas.owasp.org/MASTG/iOS/0x06h-Testing-Platform-Interaction/) ”）
- App Transport Security (ATS)配置：（`NSAppTransportSecurity`详见《[iOS网络通信](https://mas.owasp.org/MASTG/iOS/0x06g-Testing-Network-Communication/)》）

请参阅上述章节以了解有关如何测试每个点的更多信息。

##### 应用二进制[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#app-binary)

iOS 应用程序二进制文件是胖二进制文件（它们可以部署在所有 32 位和 64 位设备上）。与实际上可以将应用程序二进制文件反编译为 Java 代码的 Android 相比，iOS 应用程序二进制文件只能反汇编。

[有关详细信息，请参阅iOS 上](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/)的篡改和逆向工程一章。

##### Native库(NATIVE LIBRARIES)[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#native-libraries)

iOS 应用程序可以通过使用不同的元素使其代码库模块化。在 MASTG 中，我们将它们都称为本地库，但它们可以有不同的形式：

- [静态和动态库](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/OverviewOfDynamicLibraries.html#//apple_ref/doc/uid/TP40001873-SW1)：
- 可以使用静态库并将其编译到应用程序二进制文件中。
- 也使用动态库（通常具有`.dylib`扩展名），但必须是框架包的一部分。[iOS、watchOS 或 tvOS不支持](https://developer.apple.com/library/archive/technotes/tn2435/_index.html#//apple_ref/doc/uid/DTS40017543-CH1-PROJ_CONFIG-APPS_WITH_DEPENDENCIES_BETWEEN_FRAMEWORKS)独立动态库，Xcode 提供的系统 Swift 库除外。
- [框架](https://developer.apple.com/library/archive/technotes/tn2435/_index.html#//apple_ref/doc/uid/DTS40017543-CH1-PROJ_CONFIG-APPS_WITH_DEPENDENCIES_BETWEEN_FRAMEWORKS)（自 iOS 8 起）。框架是一个分层目录，它将动态库、头文件和资源（例如故事板、图像文件和本地化字符串）封装到一个包中。
- [Binary Frameworks ( `XCFrameworks`)](https://developer.apple.com/videos/play/wwdc2019/416/)：Xcode 11 支持使用这种`XCFrameworks`格式分发二进制库，这是一种捆绑框架的多个变体的新方法，例如，对于 Xcode 支持的任何平台（包括模拟器和设备）。他们还可以捆绑静态库（及其相应的标头）并支持 Swift 和基于 C 的代码的二进制分发。`XCFrameworks`可以[作为 Swift Packages 分发](https://developer.apple.com/documentation/swift_packages/distributing_binary_frameworks_as_swift_packages)。
- [Swift 包](https://developer.apple.com/documentation/swift_packages)：Xcode 11 添加了对 Swift 包的支持，Swift 包是 Swift、Objective-C、Objective-C++、C 或 C++ 代码的可重用组件，开发人员可以在其项目中使用并作为源代码分发。从 Xcode 12 开始，它们还可以[捆绑资源](https://developer.apple.com/videos/play/wwdc2020/10169/)，例如图像、故事板和其他文件。由于包库[默认是静态的](https://developer.apple.com/videos/play/wwdc2019/408/?time=739)。Xcode 编译它们以及它们所依赖的包，然后将所有内容链接并组合到应用程序中。

您可以通过单击“模块”在 Passionfruit 中可视化Native库(NATIVE LIBRARIES)：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_modules.png)

并获得更详细的视图，包括他们的进口/出口：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_modules_detail.png)

它们`Frameworks`在 IPA 的文件夹中可用，您也可以从终端检查它们：

```
$ ls -1 Frameworks/
Realm.framework
libswiftCore.dylib
libswiftCoreData.dylib
libswiftCoreFoundation.dylib
```

或者来自有objection的设备（当然还有 SSH）：

```
OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # ls
NSFileType      Perms  NSFileProtection    ...  Name
------------  -------  ------------------  ...  ----------------------------
Directory         493  None                ...  Realm.framework
Regular           420  None                ...  libswiftCore.dylib
Regular           420  None                ...  libswiftCoreData.dylib
Regular           420  None                ...  libswiftCoreFoundation.dylib
...
```

请注意，这可能不是应用程序使用的Native代码元素的完整列表，因为有些可能是源代码的一部分，这意味着它们将在应用程序二进制文件中编译，因此无法作为独立的库或框架找到在`Frameworks`文件夹中。

目前，这就是您可以获得的有关框架的所有信息，除非您开始对它们进行逆向工程。有关如何对框架进行逆向工程的更多信息，请参阅[iOS 上的篡改和逆向工程](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/)一章。

##### 其他应用资源[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#other-app-resources)

通常值得看一下您可能在 IPA 内的应用程序包 (.app) 中找到的其余资源和文件，因为有时它们包含额外的好东西，如加密数据库、证书等。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_db_view.png)

#### 访问应用程序数据目录[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#accessing-app-data-directories)

安装该应用程序后，可以探索更多信息。让我们简要概述 iOS 应用程序上的应用程序文件夹结构，以了解哪些数据存储在何处。下图表示应用程序文件夹结构：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06a/iOS_Folder_Structure.png)

在 iOS 上，系统应用程序可以在`/Applications`目录中找到，而用户安装的应用程序可以在目录下找到`/private/var/containers/`。然而，仅通过浏览文件系统找到正确的文件夹并不是一项简单的任务，因为每个应用程序都会为其目录名称分配一个随机的 128 位 UUID（通用唯一标识符）。

为了方便地获取用户安装的应用程序的安装目录信息，您可以通过以下方法：

连接到设备上的终端并运行命令`ipainstaller`（[IPA Installer Console](https://cydia.saurik.com/package/com.autopear.installipa)），如下所示：

```
iPhone:~ root# ipainstaller -l
...
OWASP.iGoat-Swift

iPhone:~ root# ipainstaller -i OWASP.iGoat-Swift
...
Bundle: /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67
Application: /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app
Data: /private/var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693
```

使用 objection 的命令`env`还会向您显示该应用程序的所有目录信息。连接到带有objection的应用程序在“[推荐工具 - objection](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#using-objection)”部分中有描述。

```
OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # env

Name               Path
-----------------  -------------------------------------------------------------------------------------------
BundlePath         /var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app
CachesDirectory    /var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/Library
```

如您所见，应用程序有两个主要位置：

- 捆绑目录 ( `/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/`)。
- 数据目录 ( `/var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/`)。

这些文件夹包含在应用程序安全评估期间必须仔细检查的信息（例如，在分析存储数据中的敏感数据时）。

捆绑目录：

- **应用名称.app**
- 这是之前在 IPA 中看到的应用程序包，它包含基本的应用程序数据、静态内容以及应用程序的编译二进制文件。
- 该目录对用户可见，但用户不能写入。
- 此目录中的内容未备份。
- 此文件夹的内容用于验证代码签名。

数据目录：

- **文件/**
- 包含所有用户生成的数据。应用程序最终用户启动此数据的创建。
- 对用户可见，用户可以写入。
- 该目录中的内容已备份。
- 该应用程序可以通过设置禁用路径`NSURLIsExcludedFromBackupKey`。
- **库（Libraries）/**
- 包含非特定于用户的所有文件，例如缓存、首选项、cookie 和属性列表 (plist) 配置文件。
- iOS 应用程序通常使用`Application Support`和`Caches`子目录，但应用程序可以创建自定义子目录。
- **库（Libraries）/缓存/**
- 包含半持久缓存文件。
- 对用户不可见，用户不能写入。
- 此目录中的内容未备份。
- 当应用程序未运行且存储空间不足时，操作系统可能会自动删除该目录的文件。
- **库（Libraries）/应用支持/**
- 包含运行应用程序所需的持久文件。
- 对用户不可见，用户不能写入。
- 该目录中的内容已备份。
- 该应用程序可以通过设置禁用路径`NSURLIsExcludedFromBackupKey`。
- **库（Libraries）/首选项/**
- 用于存储即使在应用程序重新启动后也可以保留的属性。
- 信息以未加密的方式保存在应用程序沙箱中名为 [BUNDLE_ID].plist 的 plist 文件中。
- 所有使用存储的键/值对`NSUserDefaults`都可以在这个文件中找到。
- **临时工/**
- 使用此目录写入不需要在应用程序启动之间保留的临时文件。
- 包含非持久缓存文件。
- 对用户不可见。
- 此目录中的内容未备份。
- 当应用程序未运行且存储空间不足时，操作系统可能会自动删除该目录的文件。

让我们仔细看看Bundle 目录 ( ) 中[iGoat-Swift](https://mas.owasp.org/MASTG/Tools/0x08b-Reference-Apps/#igoat-swift)的 Application Bundle (.app) 目录`/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app`：

```
OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # ls
NSFileType      Perms  NSFileProtection    ...  Name
------------  -------  ------------------  ...  --------------------------------------
Regular           420  None                ...  rutger.html
Regular           420  None                ...  mansi.html
Regular           420  None                ...  splash.html
Regular           420  None                ...  about.html

Regular           420  None                ...  LICENSE.txt
Regular           420  None                ...  Sentinel.txt
Regular           420  None                ...  README.txt

Directory         493  None                ...  URLSchemeAttackExerciseVC.nib
Directory         493  None                ...  CutAndPasteExerciseVC.nib
Directory         493  None                ...  RandomKeyGenerationExerciseVC.nib
Directory         493  None                ...  KeychainExerciseVC.nib
Directory         493  None                ...  CoreData.momd
Regular           420  None                ...  archived-expanded-entitlements.xcent
Directory         493  None                ...  SVProgressHUD.bundle

Directory         493  None                ...  Base.lproj
Regular           420  None                ...  Assets.car
Regular           420  None                ...  PkgInfo
Directory         493  None                ...  _CodeSignature
Regular           420  None                ...  AppIcon60x60@3x.png

Directory         493  None                ...  Frameworks

Regular           420  None                ...  embedded.mobileprovision

Regular           420  None                ...  Credentials.plist
Regular           420  None                ...  Assets.plist
Regular           420  None                ...  Info.plist

Regular           493  None                ...  iGoat-Swift
```

您还可以通过单击**Files** -> **App Bundle**可视化 Passionfruit 中的 Bundle 目录：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_bundle_dir.png)

包括`Info.plist`文件：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_plist_view.png)

以及**Files** -> **Data**中的 Data 目录：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_data_dir.png)

有关安全存储敏感数据的更多信息和最佳实践，请参阅[测试数据存储一章。](https://mas.owasp.org/MASTG/iOS/0x06d-Testing-Data-Storage/)

#### 监控系统日志[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#monitoring-system-logs)

许多应用程序将信息性（并且可能是敏感的）消息记录到控制台日志中。该日志还包含崩溃报告和其他有用信息。**您可以通过 Xcode Devices**窗口收集控制台日志，如下所示：

1. 启动 Xcode。
2. 将您的设备连接到主机。
3. 选择**Window** -> **Devices and Simulators**。
4. 单击“设备”窗口左侧部分中已连接的 iOS 设备。
5. 重现问题。
6. 单击“设备”窗口右上角的“**打开控制台**”按钮，在单独的窗口中查看控制台日志。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/open_device_console.png)

要将控制台输出保存到文本文件，请转到控制台窗口的右上角，然后单击“**保存**”按钮。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/device_console.png)

您还可以按照[访问](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#accessing-the-device-shell)设备Shell中的说明连接到设备Shell，通过 apt-get 安装 socat 并运行以下命令：

```
iPhone:~ root# socat - UNIX-CONNECT:/var/run/lockdown/syslog.sock

========================
ASL is here to serve you
> watch
OK

Jun  7 13:42:14 iPhone chmod[9705] <Notice>: MS:Notice: Injecting: (null) [chmod] (1556.00)
Jun  7 13:42:14 iPhone readlink[9706] <Notice>: MS:Notice: Injecting: (null) [readlink] (1556.00)
Jun  7 13:42:14 iPhone rm[9707] <Notice>: MS:Notice: Injecting: (null) [rm] (1556.00)
Jun  7 13:42:14 iPhone touch[9708] <Notice>: MS:Notice: Injecting: (null) [touch] (1556.00)
...
```

此外，Passionfruit 还提供了所有基于 NSLog 的应用程序日志的视图。只需单击**控制台**->**输出**选项卡：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/passionfruit_console_logs.png)

#### 转储钥匙串数据[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#dumping-keychain-data)

可以使用多种工具转储 KeyChain 数据，但并非所有工具都适用于任何 iOS 版本。通常情况下，请尝试不同的工具或查找其文档以获取有关最新支持版本的信息。

##### objection（越狱/非越狱）[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#objection-jailbroken-non-jailbroken)

使用 Objection 可以轻松查看 KeyChain 数据。首先，如“推荐工具 - objection”中所述，将objection连接到应用程序。然后，使用`ios keychain dump`命令来获取钥匙串的概览：

```
$ objection --gadget="iGoat-Swift" explore
... [usb] # ios keychain dump
...
Note: You may be asked to authenticate using the devices passcode or TouchID
Save the output by adding `--json keychain.json` to this command
Dumping the iOS keychain...
Created                    Accessible                      ACL    Type      Account              Service                     Data
-------------------------  ------------------------------  -----  --------  -------------------  --------------------------  ----------------------------------------------------------------------
2019-06-06 10:53:09 +0000  WhenUnlocked                    None   Password  keychainValue        com.highaltitudehacks.dvia  mypassword123
2019-06-06 10:53:30 +0000  WhenUnlockedThisDeviceOnly      None   Password  SCAPILazyVector      com.toyopagroup.picaboo     (failed to decode)
2019-06-06 10:53:30 +0000  AfterFirstUnlockThisDeviceOnly  None   Password  fideliusDeviceGraph  com.toyopagroup.picaboo     (failed to decode)
2019-06-06 10:53:30 +0000  AfterFirstUnlockThisDeviceOnly  None   Password  SCDeviceTokenKey2    com.toyopagroup.picaboo     00001:FKsDMgVISiavdm70v9Fhv5z+pZfBTTN7xkwSwNvVr2IhVBqLsC7QBhsEjKMxrEjh
2019-06-06 10:53:30 +0000  AfterFirstUnlockThisDeviceOnly  None   Password  SCDeviceTokenValue2  com.toyopagroup.picaboo     CJ8Y8K2oE3rhOFUhnxJxDS1Zp8Z25XzgY2EtFyMbW3U=
OWASP.iGoat-Swift on (iPhone: 12.0) [usb] # quit  
```

请注意，目前最新版本的 frida-server 和 objection 无法正确解码所有钥匙串数据。可以尝试不同的组合来增加兼容性。例如，先前的打印输出是使用`frida-tools==1.3.0`,`frida==12.4.8`和创建的`objection==1.5.0`。

最后，由于 keychain dumper 是在应用程序上下文中执行的，它只会打印出应用程序可以访问的 keychain 项，而**不是**iOS 设备的整个 keychain。

##### 百香果（越狱/非越狱）[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#passionfruit-jailbroken-non-jailbroken)

使用[Passionfruit](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#passionfruit)可以访问您选择的应用程序的钥匙串数据。单击**存储**->**钥匙串**，您可以看到存储的钥匙串信息的列表。

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/Passionfruit_Keychain.png)

##### KEYCHAIN-DUMPER（越狱）[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#keychain-dumper-jailbroken)

您可以使用[Keychain-dumper](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#keychain-dumper)转储越狱设备的 KeyChain 内容。在您的设备上运行它后：

```
iPhone:~ root# /tmp/keychain_dumper

(...)

Generic Password
----------------
Service: myApp
Account: key3
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: SmJSWxEs

Generic Password
----------------
Service: myApp
Account: key7
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: WOg1DfuH
```

在较新版本的 iOS（iOS 11 及更高版本）中，需要额外的步骤。有关详细信息，请参阅 README.md。请注意，此二进制文件是使用具有“通配符”权利的自签名证书签名的。该权利授予对钥匙串中*所有*项目的访问权限。如果您偏执或在您的测试设备上有非常敏感的私人数据，您可能希望从源代码构建该工具并手动将适当的权利签署到您的构建中；GitHub 存储库中提供了执行此操作的说明。

## 搭建网络测试环境[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#setting-up-a-network-testing-environment)

### 基本网络监控/嗅探[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#basic-network-monitoringsniffing)

您可以通过为您的 iOS 设备[创建一个远程虚拟接口](https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark/33175819#33175819)来远程实时嗅探 iOS 上的所有流量。首先确保您的 macOS 主机上安装了[Wireshark 。](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#wireshark)

1. 通过 USB 将您的 iOS 设备连接到 macOS 主机。
2. 在开始嗅探之前，您需要知道 iOS 设备的 UDID。查看[“获取 iOS 设备的 UDID”](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#getting-the-udid-of-an-ios-device)部分，了解如何检索它。在 macOS 上打开终端并输入以下命令，填写您的 iOS 设备的 UDID。

```
$ rvictl -s <UDID>
Starting device <UDID> [SUCCEEDED] with interface rvi0
```

1. 启动 Wireshark 并选择“rvi0”作为捕获接口。
2. 使用 Wireshark 中的捕获过滤器过滤流量以显示您要监控的内容（例如，通过 IP 地址 192.168.1.1 发送/接收的所有 HTTP 流量）。

```
ip.addr == 192.168.1.1 && http
```

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/wireshark_filters.png)

Wireshark 的文档提供了许多[捕获过滤器](https://wiki.wireshark.org/CaptureFilters)的示例，这些示例应该可以帮助您过滤流量以获取所需的信息。

### 设置拦截代理[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#setting-up-an-interception-proxy)

[Burp Suite](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#burp-suite)是一个用于安全测试移动和 Web 应用程序的集成平台。它的工具无缝协作以支持整个测试过程，从攻击面的初始映射和分析到查找和利用安全漏洞。Burp Proxy 作为 Burp Suite 的 Web 代理服务器运行，Burp Suite 定位为浏览器和 Web 服务器之间的中间人。Burp Suite 允许您拦截、检查和修改传入和传出的原始 HTTP 流量。

设置 Burp 来代理您的流量非常简单。我们假设您的 iOS 设备和主机都连接到允许客户端到客户端流量的 Wi-Fi 网络。如果不允许客户端到客户端的流量，您可以使用 usbmuxd 通过 USB 连接到 Burp。

PortSwigger 提供了一个[关于设置 iOS 设备以使用 Burp 的很好的教程](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp)和一个[关于将 Burp 的 CA 证书安装到 iOS 设备](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device)的教程。

#### 在越狱设备上通过 USB 使用 Burp[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#using-burp-via-usb-on-a-jailbroken-device)

在[访问设备Shell](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#accessing-the-device-shell)一节中，我们已经了解了如何使用[iproxy](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#iproxy)通过 USB 使用 SSH。在进行动态分析时，使用 SSH 连接将流量路由到计算机上运行的 Burp 很有趣。让我们开始吧：

首先，我们需要使用 iproxy 使 iOS 的 SSH 在本地主机上可用。

```
$ iproxy 2222 22
waiting for connection
```

接下来要做的就是将iOS设备上的8080端口做一个远程端口转发到我们电脑上的localhost接口到8080端口上。

```
ssh -R 8080:localhost:8080 root@localhost -p 2222
```

您现在应该可以在您的 iOS 设备上访问 Burp。在 iOS 上打开 Safari 并转到 127.0.0.1:8080，您应该会看到 Burp Suite 页面。这也是在您的 iOS 设备上[安装 Burp 的 CA 证书的好时机。](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device)

最后一步是在您的 iOS 设备上全局设置代理：

1. 转到**设置**- > **Wi-Fi**
2. 连接到*任何*Wi-Fi（您实际上可以连接到任何 Wi-Fi，因为端口 80 和 443 的流量将通过 USB 路由，因为我们只是使用 Wi-Fi 的代理设置，因此我们可以设置全局代理)
3. 连接后，单击连接 Wi-Fi 右侧的蓝色小图标
4. **通过选择手动**配置您的代理
5. 输入 127.0.0.1 作为**服务器**
6. 输入 8080 作为**端口**

打开 Safari 并转到任何网页，您现在应该可以看到 Burp 中的流量。感谢@hweisheimer 的[最初想法](https://twitter.com/hweisheimer/status/1095383526885724161)！

### 绕过证书固定[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#bypassing-certificate-pinning)

一些应用程序将实施 SSL Pinning，这会阻止应用程序接受您的拦截证书作为有效证书。这意味着您将无法监控应用程序和服务器之间的流量。

对于大多数应用程序，可以在几秒钟内绕过证书固定，但前提是应用程序使用这些工具涵盖的 API 函数。如果应用程序使用自定义框架或库实施 SSL Pinning，则必须手动修补和停用 SSL Pinning，这可能很耗时。

本节介绍了绕过 SSL Pinning 的各种方法，并提供了有关在现有工具不起作用时应该采取的措施的指导。

#### 越狱和非越狱设备的方法[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#methods-for-jailbroken-and-non-jailbroken-devices)

如果你有安装了 frida-server 的越狱设备，你可以通过运行以下[Objection](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#objection)命令来绕过 SSL 固定（如果你使用的是非越狱设备，请[重新打包你的应用程序）：](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#repackaging-apps)

```
ios sslpinning disable
```

下面是一个输出示例：

![img](https://mas.owasp.org/assets/Images/Chapters/0x06b/ios_ssl_pinning_bypass.png)

另请参阅[Objection 关于为 iOS 禁用 SSL Pinning 的帮助以](https://github.com/sensepost/objection/blob/master/objection/console/helpfiles/ios.sslpinning.disable.txt)获取更多信息，并检查[pinning.ts](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts)文件以了解旁路的工作原理。

#### 仅适用于越狱设备的方法[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#methods-for-jailbroken-devices-only)

如果您有越狱设备，您可以尝试使用以下可以自动禁用 SSL Pinning 的工具之一：

- “ [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) ”是禁用证书固定的一种方法。它可以通过[Cydia](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#cydia)商店安装。它将挂接到所有高级 API 调用并绕过证书固定。
- Burp [Suite Mobile Assistant](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#burp-suite-mobile-assistant)应用程序也可用于绕过证书固定。

#### 当自动旁路失败时[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#when-the-automated-bypasses-fail)

技术和系统会随着时间而改变，一些旁路技术最终可能无法奏效。因此，进行一些研究是测试人员工作的一部分，因为并非每个工具都能够足够快地跟上操作系统版本。

一些应用程序可能会实施自定义 SSL 固定方法，因此测试人员还可以开发新的绕过脚本，利用现有脚本作为基础或灵感，并使用类似的技术，但以应用程序的自定义 API 为目标。在这里您可以检查此类脚本的三个很好的示例：

- [“反对 - 固定旁路模块”（pinning.ts）](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts)
- [“Frida CodeShare - ios10-ssl-bypass”](https://codeshare.frida.re/@dki/ios10-ssl-bypass/) @dki
- [“使用 OkHttp 在混淆的应用程序中规避 SSL Pinning”](https://blog.nviso.eu/2019/04/02/circumventing-ssl-pinning-in-obfuscated-apps-with-okhttp)，作者：Jeroen Beckers

**其他技术：**

如果您无权访问源代码，可以尝试二进制修补：

- 如果使用 OpenSSL 证书固定，您可以尝试[二进制补丁](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/)。
- 有时，证书是应用程序包中的一个文件。用 Burp 的证书替换证书可能就足够了，但要注意证书的 SHA 和。如果它被硬编码到二进制文件中，您也必须替换它！
- 如果您可以访问源代码，您可以尝试禁用证书固定并重新编译应用程序，查找 API 调用`NSURLSession`，`CFStream`以及`AFNetworking`包含“固定”、“X.509”、“证书”等词的方法/字符串。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/#references)

- 越狱漏洞 - https://www.theiphonewiki.com/wiki/Jailbreak_Exploits
- limera1n 漏洞 - https://www.theiphonewiki.com/wiki/Limera1n
- IPSW 下载网站 - [https://ipsw.me](https://ipsw.me/)
- 我可以越狱吗？- https://canijailbreak.com/
- The iPhone Wiki - https://www.theiphonewiki.com/
- Redmond Pie - https://www.redmondpie.com/
- Reddit 越狱 - https://www.reddit.com/r/jailbreak/
- 信息属性列表 - https://developer.apple.com/documentation/bundleresources/information_property_list?language=objc
- UIDeviceFamily - https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/uid/TP40009252-SW11
