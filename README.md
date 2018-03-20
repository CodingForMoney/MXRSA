# MXRSA

使用 [mbedtls](https://tls.mbed.org) 实现`RSA`简单封装。

由于苹果没有提供官方的`RSA`加密接口，导致`RSA`加密在`iOS`上是一件很痛苦的事情。一般都使用两种方式：

1. 使用`openssl`库， 但是该库太大，拥有过多其他不需要的加密算法
2. 使用`Security`库进行RSA加密， 如 [Objective-C-RSA](https://github.com/ideawu/Objective-C-RSA) .但是问题是`keychain`本身是一件不靠谱的事情，在某些系统中会偶现`keychain`错误 [-34018](https://forums.developer.apple.com/thread/4743?start=0&tstart=0)的情况，也就导致`RSA`加解密偶尔会失败。

所以我花了一些时间，找到了`mbedtls`这个比较轻量级的加密库，在其基础上抽离出基础的`RSA`加解密功能，并进行共享。

## 使用示例 ：

见`example`项目，如下代码:

	NSData *input = [@"hello world !!!" dataUsingEncoding:NSUTF8StringEncoding];
    NSString *private = [[NSBundle mainBundle] pathForResource:@"pri.pem" ofType:nil];
    NSString *public = [[NSBundle mainBundle] pathForResource:@"pub.pem" ofType:nil];
    NSData *cipher;
    NSData *plain;
    
    cipher = [MXRSA encryptData:input usingPublicKeyFile:public];
    plain = [MXRSA decryptData:cipher usingPrivateKeyFile:private];
    NSLog(@"%@",[[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding]);
    
    cipher = [MXRSA encryptData:input usingPlulicKeyString:PublicKey];
    plain = [MXRSA decryptData:cipher usingPrivateKeyString:PrivateKey];
    NSLog(@"%@",[[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding]);
    
    cipher = [MXRSA encryptData:input usingPrivateKeyFile:private];
    plain = [MXRSA decryptData:cipher usingPublicKeyFile:public];
    NSLog(@"%@",[[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding]);
    
    cipher = [MXRSA encryptData:input usingPrivateKeyString:PrivateKey];
    plain = [MXRSA decryptData:cipher usingPlulicKeyString:PublicKey];
    NSLog(@"%@",[[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding]);
    
    
    NSString *publicStr;
    NSString *privateStr;
    [MXRSA generatePrivateKey:&privateStr PublicKey:&publicStr byKeySize:MXRSAKeySize1024];
    cipher = [MXRSA encryptData:input usingPrivateKeyString:privateStr];
    plain = [MXRSA decryptData:cipher usingPlulicKeyString:publicStr];
    NSLog(@"%@",[[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding]);


## 注意事项

在`config.h`中，提供了前缀定制宏 `PREFIX_DEFINE` , 如果需要定制自己的前缀，则需要修改该宏 ，如修改为：

	#define PREFIX_DEFINE(func)   ABC_##func

这里也就是为什么不使用靠谱且较多人使用的`openssl`的原因， 如果要单独做一个SDK，该SDK中需要`RSA`加密，那就不能依赖`openssl`，一是会增大体积，二是会有符号冲突。

公私钥文件的格式，都是pkcs8格式的。 一定要注意换行符。

## 支持Cocoapods 

	pod MXRSA
