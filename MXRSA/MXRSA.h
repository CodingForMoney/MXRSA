//
//  MXRSA.h
//  RSA2
//
//  Created by 罗贤明 on 2018/2/23.
//  Copyright © 2018年 罗贤明. All rights reserved.
//
/*
 *  Copyright © 2018年 罗贤明. All rights reserved.
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#import <Foundation/Foundation.h>

// RSA 加密位数
typedef NS_ENUM(size_t, MXRSAKeySize) {
    MXRSAKeySize512 = 512,
    MXRSAKeySize768 = 768,
    MXRSAKeySize1024 = 1024,
    MXRSAKeySize2048 = 2048,
};

/**
  MXRSA , 封装 mbedtls中的rsa实现。 mbedtls 库地址为 https://tls.mbed.org
   这里的RSA 使用的是 PKCS#1 填充， 1.5版本。
    这里所使用的公私钥都是 PEM 格式。
 */
@interface MXRSA : NSObject

#pragma mark - 公钥加密

/**
 公钥加密

 @param plain 明文 ， 在rsa中，明文长度受到限制， 如1024位的rsa， 不使用填充时，只能加密128个字节，
                        而使用PKCS1填充时， 最多只能加密 128-11=117字节的数据， 需要记住这一点。 而加密结果长度为位数， 如2048位rsa， 加密结果为256字节。
 @param filepath 公钥文件路径
 @return 如果加密成功，返回加密结果，如果加密失败，返回nil.
 */
+ (NSData *)encryptData:(NSData *)plain usingPublicKeyFile:(NSString *)filepath;


/**
 公钥加密

 @param plain 明文
 @param keyString 公钥文件内容 , 公钥字符串的第一行-----BEGIN PUBLIC KEY----- 后必须有换行符 ,示例如下
 公私钥文件的格式，都是pkcs8格式的。 一定要注意换行符。
 static NSString *const PublicKey = @"-----BEGIN PUBLIC KEY-----\r\n\
 MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxdwcxXxhCf5cWgkXYLI5+hyXg\
 p+1SMuKh98r2lWnIPHeCAX+Hr40mKhmBiXsgyRH9RLlDchP2FtnWm6JbicPUkgfv\
 ihqiwbrALKHB88zIfQL/FcQTGCt+N5xuYgT+v3bsVn0ktIL6J8Qh7F3O4Q21uVye\
 r6tpY2z3RLYOZwKPMwIDAQAB\
 -----END PUBLIC KEY-----";
 
 @return 如果加密成功，返回加密结果，如果加密失败，返回nil.
 */
+ (NSData *)encryptData:(NSData *)plain usingPlulicKeyString:(NSString *)keyString;


#pragma mark - 公钥解密
/**
 公钥解密

 @param cipher 密文数据， 在RSA加密中， 密文长度是跟随 加密位数决定的，所以函数会检测密文长度。
 @param filepath 公钥文件路径
 @return 如果解密成功，返回明文。失败返回nil。
 */
+ (NSData *)decryptData:(NSData *)cipher usingPublicKeyFile:(NSString *)filepath;


/**
 公钥解密
 
 @param cipher 密文
 @param keyString 公钥文件内容
 @return 如果解密成功，返回解密结果，失败返回nil.
 */
+ (NSData *)decryptData:(NSData *)cipher usingPlulicKeyString:(NSString *)keyString;



#pragma mark - 私钥加密


/**
  私钥加密

 @param plain 明文
 @param filepath 私钥文件， 私钥文件格式为 --BEGIN PRIVATE KEY--
 @return 加密成功，返回加密结果，失败返回nil
 */
+ (NSData *)encryptData:(NSData *)plain usingPrivateKeyFile:(NSString *)filepath;


/**
 私钥加密
 
 @param plain 明文
 @param keyString 私钥文件内容 私钥字符串的第一行-----BEGIN PRIVATE KEY----- 后必须有换行符
 @return 如果加密成功，返回加密结果，如果加密失败，返回nil.
 */
+ (NSData *)encryptData:(NSData *)plain usingPrivateKeyString:(NSString *)keyString;


#pragma mark - 私钥解密

/**
  私钥解密

 @param cipher 密文
 @param filepath 私钥文件地址
 @return 如果解密成功，返回明文，失败返回nil
 */
+ (NSData *)decryptData:(NSData *)cipher usingPrivateKeyFile:(NSString *)filepath;


/**
 私钥解密
 
 @param cipher 密文
 @param keyString 私钥文件内入  私钥字符串的第一行-----BEGIN PRIVATE KEY----- 后必须有换行符
 @return 如果解密成功，返回明文，失败返回nil
 */
+ (NSData *)decryptData:(NSData *)cipher usingPrivateKeyString:(NSString *)keyString;


#pragma mark - 密钥对生成
/**
 密钥对生成 , 需要注意密钥生成时耗时操作， 建议放在异步线程中，不要阻塞主线程。
 exponent 固定为 65537
 @param privateKey 私钥
 @param publicKey 公钥
 @param size RSA位数
 @return 如果生成成功，返回YES。
 */
+ (BOOL)generatePrivateKey:(NSString **)privateKey PublicKey:(NSString **)publicKey byKeySize:(MXRSAKeySize)size;

@end
