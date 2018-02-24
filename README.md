# MXRSA

使用 [mbedtls](https://tls.mbed.org) 实现`RSA`简单封装。

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

## 支持Cocoapods 

	pod MXRSA
