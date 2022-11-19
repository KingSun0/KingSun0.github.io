# iOS 本地认证[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#ios-local-authentication)

在本地身份验证期间，应用程序根据设备本地存储的凭据对用户进行身份验证。换句话说，用户通过提供有效的 PIN、密码或面部或指纹等生物特征来“解锁”应用程序或某些内层功能，这些特征通过引用本地数据进行验证。通常，这样做是为了让用户可以更方便地恢复与远程服务的现有会话，或者作为一种加强身份验证的方式来保护某些关键功能。

正如之前在“[移动应用程序身份验证架构](https://mas.owasp.org/MASTG/General/0x04e-Testing-Authentication-and-Session-Management/)”一章中所述：测试人员应该知道本地身份验证应该始终在远程端点或基于加密原语强制执行。如果身份验证过程没有返回数据，攻击者可以轻松绕过本地身份验证。

## 测试本地身份验证（MSTG-AUTH-8 和 MSTG-STORAGE-11）[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#testing-local-authentication-mstg-auth-8-and-mstg-storage-11)

在 iOS 上，有多种方法可用于将本地身份验证集成到应用程序中。[本地身份验证框架](https://developer.apple.com/documentation/localauthentication)为开发人员提供了一组 API ，用于向用户扩展身份验证对话框。在连接到远程服务的上下文中，可以（并且推荐）利用[钥匙串](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html)来实现本地身份验证。

iOS 上的指纹身份验证称为*Touch ID*。指纹 ID 传感器由[SecureEnclave 安全协处理器](https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf)操作，不会将指纹数据暴露给系统的任何其他部分。在 Touch ID 旁边，Apple 推出了*Face ID*：它允许基于面部识别的身份验证。两者在应用程序级别上使用相似的 API，存储数据和检索数据（例如面部数据或指纹相关数据）的实际方法不同。

开发人员有两种选择来合并 Touch ID/Face ID 身份验证：

- `LocalAuthentication.framework`是一个高级 API，可用于通过 Touch ID 对用户进行身份验证。该应用程序无法访问与已注册指纹关联的任何数据，并且只会在身份验证是否成功时收到通知。
- `Security.framework`是访问[钥匙串服务](https://developer.apple.com/documentation/security/keychain_services)的较低级别的 API 。如果您的应用程序需要通过生物识别身份验证来保护某些秘密数据，这是一个安全的选择，因为访问控制是在系统级别进行管理的，并且不容易被绕过。`Security.framework`有一个 C API，但有几个可用的[开源包装器](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id)，使访问钥匙串与访问 NSUserDefaults 一样简单。`Security.framework`基础 `LocalAuthentication.framework`; Apple 建议尽可能默认使用更高级别的 API。

请注意，使用 the`LocalAuthentication.framework`或`Security.framework`, 将是一个可以被攻击者绕过的控件，因为它只返回一个布尔值而没有数据可以继续。有关详细信息，请参阅[David Lindner 等人](https://www.youtube.com/watch?v=XhXIHVGCFFM)的 Don't touch me that way。

### 本地身份验证框架[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#local-authentication-framework)

本地身份验证框架提供了向用户请求密码或 Touch ID 身份验证的工具。开发者可以利用该类的功能`evaluatePolicy`来显示和使用认证提示。`LAContext`

两个可用的策略定义了可接受的身份验证形式：

- `deviceOwnerAuthentication`(Swift) 或`LAPolicyDeviceOwnerAuthentication`(Objective-C)：可用时，提示用户执行 Touch ID 身份验证。如果未激活 Touch ID，则改为请求设备密码。如果未启用设备密码，策略评估将失败。
- `deviceOwnerAuthenticationWithBiometrics`(Swift) 或`LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C)：身份验证仅限于提示用户输入 Touch ID 的生物特征识别。

该`evaluatePolicy`函数返回一个布尔值，指示用户是否已成功验证。

Apple Developer 网站提供了[Swift](https://developer.apple.com/documentation/localauthentication)和[Objective-C 的](https://developer.apple.com/documentation/localauthentication?language=objc)代码示例。Swift 中的典型实现如下所示。

```
let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
    // Could not evaluate policy; look at error and present an appropriate message to user
}

context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Please, pass authorization to enter this area") { success, evaluationError in
    guard success else {
        // User did not authenticate successfully, look at evaluationError and take appropriate action
    }

    // User authenticated successfully, take appropriate action
}
```

- *使用本地身份验证框架（Apple 的官方代码示例）在 Swift 中进行 Touch ID 身份验证。*

### 使用钥匙串服务进行本地身份验证[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#using-keychain-services-for-local-authentication)

iOS 钥匙串 API 可以（并且应该）用于实现本地身份验证。在此过程中，应用程序会在钥匙串中存储一个秘密身份验证令牌或另一段用于识别用户的秘密数据。为了向远程服务进行身份验证，用户必须使用他们的密码或指纹解锁钥匙串以获得秘密数据。

钥匙串允许保存具有特殊`SecAccessControl`属性的项目，只有在用户通过 Touch ID 身份验证（或密码，如果属性参数允许这种后备）后，才允许从钥匙串访问项目。

在下面的示例中，我们将字符串“test_strong_password”保存到钥匙串中。`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`在设置密码（参数）并且仅对当前注册的手指进行 Touch ID 身份验证（参数）后，只能在当前设备上访问该字符串`SecAccessControlCreateFlags.biometryCurrentSet`：

#### 迅速[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#swift)

```
// 1. Create the AccessControl object that will represent authentication settings

var error: Unmanaged<CFError>?

guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                          kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                          SecAccessControlCreateFlags.biometryCurrentSet,
                                                          &error) else {
    // failed to create AccessControl object

    return
}

// 2. Create the keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute

var query: [String: Any] = [:]

query[kSecClass as String] = kSecClassGenericPassword
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecAttrAccount as String] = "OWASP Account" as CFString
query[kSecValueData as String] = "test_strong_password".data(using: .utf8)! as CFData
query[kSecAttrAccessControl as String] = accessControl

// 3. Save the item

let status = SecItemAdd(query as CFDictionary, nil)

if status == noErr {
    // successfully saved
} else {
    // error while saving
}

// 4. Now we can request the saved item from the keychain. Keychain services will present the authentication dialog to the user and return data or nil depending on whether a suitable fingerprint was provided or not.

// 5. Create the query
var query = [String: Any]()
query[kSecClass as String] = kSecClassGenericPassword
query[kSecReturnData as String] = kCFBooleanTrue
query[kSecAttrAccount as String] = "My Name" as CFString
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecUseOperationPrompt as String] = "Please, pass authorisation to enter this area" as CFString

// 6. Get the item
var queryResult: AnyObject?
let status = withUnsafeMutablePointer(to: &queryResult) {
    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
}

if status == noErr {
    let password = String(data: queryResult as! Data, encoding: .utf8)!
    // successfully received password
} else {
    // authorization not passed
}
```

#### Objective-C[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#objective-c)

```
// 1. Create the AccessControl object that will represent authentication settings
CFErrorRef *err = nil;

SecAccessControlRef sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    kSecAccessControlUserPresence,
    err);

// 2. Create the keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute
NSDictionary* query = @{
    (_ _bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
    (__bridge id)kSecAttrAccount: @"OWASP Account",
    (__bridge id)kSecValueData: [@"test_strong_password" dataUsingEncoding:NSUTF8StringEncoding],
    (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacRef
};

// 3. Save the item
OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nil);

if (status == noErr) {
    // successfully saved
} else {
    // error while saving
}

// 4. Now we can request the saved item from the keychain. Keychain services will present the authentication dialog to the user and return data or nil depending on whether a suitable fingerprint was provided or not.

// 5. Create the query
NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecAttrAccount: @"My Name1",
    (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
    (__bridge id)kSecUseOperationPrompt: @"Please, pass authorisation to enter this area" };

// 6. Get the item
CFTypeRef queryResult = NULL;
OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &queryResult);

if (status == noErr){
    NSData* resultData = ( __bridge_transfer NSData* )queryResult;
    NSString* password = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    NSLog(@"%@", password);
} else {
    NSLog(@"Something went wrong");
}
```

应用程序中框架的使用也可以通过分析应用程序二进制文件的共享动态库列表来检测。这可以通过使用[otool](https://mas.owasp.org/MASTG/Tools/0x08a-Testing-Tools/#otool)来完成：

```
otool -L <AppName>.app/<AppName>
```

如果`LocalAuthentication.framework`在应用程序中使用，输出将包含以下两行（请记住在后台`LocalAuthentication.framework`使用`Security.framework`）：

```
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

如果`Security.framework`使用，则仅显示第二个。

### 静态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#static-analysis)

重要的是要记住 LocalAuthentication 框架是一个基于事件的过程，因此不应该是唯一的身份验证方法。虽然这种类型的身份验证在用户界面级别有效，但很容易通过修补或检测绕过。因此，最好使用keychain服务方式，也就是说你应该：

- 使用钥匙串服务方法验证敏感进程（例如重新验证执行支付交易的用户）是否受到保护。
- 验证是否为钥匙串项设置了访问控制标志，确保钥匙串项的数据只能通过对用户进行身份验证来解锁。这可以使用以下标志之一来完成：
- `kSecAccessControlBiometryCurrentSet`（iOS 11.3 之前`kSecAccessControlTouchIDCurrentSet`）。这将确保用户在访问钥匙串项中的数据之前需要使用生物识别技术（例如 Face ID 或 Touch ID）进行身份验证。每当用户向设备添加指纹或面部表示时，它会自动使钥匙串中的条目失效。这确保钥匙串项目只能由在项目添加到钥匙串时注册的用户解锁。
- `kSecAccessControlBiometryAny`（iOS 11.3 之前`kSecAccessControlTouchIDAny`）。这将确保用户在访问钥匙串条目中的数据之前需要使用生物识别技术（例如 Face ID 或 Touch ID）进行身份验证。Keychain 条目将在任何（重新）注册新指纹或面部表示时继续存在。如果用户的指纹不断变化，这会非常方便。然而，这也意味着攻击者能够以某种方式将他们的指纹或面部特征登记到设备中，现在也可以访问这些条目。
- `kSecAccessControlUserPresence`可以作为替代品。如果生物认证不再有效，这将允许用户通过密码进行认证。这被认为比`kSecAccessControlBiometryAny`绕过 Touch ID 或 Face ID 服务更容易，因为通过 shouldersurfing 窃取某人的密码条目要容易得多。
- 为了确保可以使用生物识别技术，请验证在调用该方法时是否设置`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`了`kSecAttrAccessibleWhenPasscodeSet`保护等级。`SecAccessControlCreateWithFlags`请注意，该`...ThisDeviceOnly`变体将确保钥匙串项不与其他 iOS 设备同步。

> 请注意，数据保护类指定用于保护数据的访问方法。每个类使用不同的策略来确定何时可以访问数据。

### 动态分析[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#dynamic-analysis)

[Objection Biometrics Bypass](https://github.com/sensepost/objection/wiki/Understanding-the-iOS-Biometrics-Bypass)可用于绕过 LocalAuthentication。Objection 使用 Frida 来检测该`evaluatePolicy`函数，以便`True`即使未成功执行身份验证也能返回。使用该`ios ui biometrics_bypass`命令绕过不安全的生物认证。objection将登记一份工作，这将取代`evaluatePolicy`结果。它适用于 Swift 和 Objective-C 实现。

```
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios ui biometrics_bypass
(agent) Registering job 3mhtws9x47q. Type: ios-biometrics-disable
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # (agent) [3mhtws9x47q] Localized Reason for auth requirement: Please authenticate yourself
(agent) [3mhtws9x47q] OS authentication response: false
(agent) [3mhtws9x47q] Marking OS response as True instead
(agent) [3mhtws9x47q] Biometrics bypass hook complete
```

如果存在漏洞，该模块将自动绕过登录表单。

## 关于钥匙串中钥匙临时性的注意事项[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#note-regarding-temporariness-of-keys-in-the-keychain)

与 macOS 和 Android 不同，iOS 目前（在 iOS 12）不支持钥匙串中项目的可访问性的临时性：当进入钥匙串时没有额外的安全检查（例如`kSecAccessControlUserPresence`或类似设置），那么一旦设备被解锁，一把钥匙将是可访问的。

## 参考[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#references)

### OWASP MASVS[¶](https://mas.owasp.org/MASTG/iOS/0x06f-Testing-Local-Authentication/#owasp-masvs)

- MSTG-AUTH-8：“生物识别身份验证（如果有的话）不是事件绑定的（即使用简单返回“真”或“假”的 API）。相反，它基于解锁钥匙串/密钥库。”
- MSTG-STORAGE-11：“该应用程序执行最低限度的设备访问安全策略，例如要求用户设置设备密码。”
