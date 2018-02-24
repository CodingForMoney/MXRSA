//
//  MXRSA.m
//  RSA2
//
//  Created by 罗贤明 on 2018/2/23.
//
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


#import "MXRSA.h"
#import "rsa.h"
#import "pk.h"
#import <stdlib.h>

// 一个简单实现的随机函数，以简化RSA的加密实现逻辑。
static int local_simple_random_function( void *p_rng,
                                        unsigned char *output, size_t output_len ) {
    static void *current_rng = NULL;
    if (p_rng != current_rng) {
        current_rng = p_rng;
        srand((unsigned int)time(0));
    }
    for (int i = 0; i < output_len; i++) {
        output[i] = rand();
    }
    return 0;
}

@implementation MXRSA

#pragma mark - 公钥
+ (NSData *)encryptData:(NSData *)plain usingPublicKeyFile:(NSString *)filepath {
    if (!plain || !filepath) {
        NSLog(@"参数传入错误 ！！！");
        return nil;
    }
    if (plain.length == 0) {
        NSLog(@"加密原文长度不能为空！！！");
        return nil;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:filepath]) {
        NSLog(@"公钥文件不存在 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_public_keyfile(&ctx,filepath.UTF8String);
    if (ret_code) {
        NSLog(@"公钥文件读取失败， mbedtls错误码为 %@ , 请检测公钥文件是否存在，或者公钥文件格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (plain.length + 11 > rsa->len) {
        NSLog(@"加密原文长度不能超过 %@ !!!",@(rsa->len - 11));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_encrypt( rsa, local_simple_random_function,
                                    rsa, MBEDTLS_RSA_PUBLIC,
                                    plain.length, plain.bytes, buf );
    if (ret_code) {
        NSLog(@"加密失败！！！ mbedtls 错误码为 %@ , 请检测公钥是否正确 ！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *cipher = [NSData dataWithBytes:buf length:rsa->len];
    mbedtls_pk_free(&ctx);
    return cipher;
}

+ (NSData *)encryptData:(NSData *)plain usingPlulicKeyString:(NSString *)keyString {
    if (!plain || !keyString) {
        NSLog(@"参数传入错误 ！！！");
        return nil;
    }
    if (plain.length == 0) {
        NSLog(@"加密原文长度不能为空！！！");
        return nil;
    }
    if (keyString.length == 0) {
        NSLog(@"公钥字符串不能为空 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_public_key(&ctx,(unsigned char *)keyString.UTF8String,keyString.length + 1);
    if (ret_code) {
        NSLog(@"公钥字符串读取失败， mbedtls错误码为 %@ , 请检测公钥字符串格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (plain.length + 11 > rsa->len) {
        NSLog(@"加密原文长度不能超过 %@ !!!",@(rsa->len - 11));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_encrypt( rsa, local_simple_random_function,
                                         rsa, MBEDTLS_RSA_PUBLIC,
                                         plain.length, plain.bytes, buf );
    if (ret_code) {
        NSLog(@"加密失败！！！ mbedtls 错误码为 %@ , 请检测公钥是否正确 ！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *cipher = [NSData dataWithBytes:buf length:rsa->len];
    mbedtls_pk_free(&ctx);
    return cipher;
}

+ (NSData *)decryptData:(NSData *)cipher usingPublicKeyFile:(NSString *)filepath {
    if (!cipher || !filepath) {
        NSLog(@"参数不能传入空值！！！");
        return nil;
    }
    if (cipher.length == 0) {
        NSLog(@"密文长度不能为空！！！");
        return nil;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:filepath]) {
        NSLog(@"公钥文件不存在 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_public_keyfile(&ctx,filepath.UTF8String);
    if (ret_code) {
        NSLog(@"公钥文件读取失败， mbedtls错误码为 %@ , 请检测公钥文件是否存在，或者公钥文件格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (cipher.length != rsa->len) {
        NSLog(@"公钥文件所指定的RSA加密位数为 %@ ,密文长度必须为 %@", @(rsa->len * 8) , @(rsa->len));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    size_t outlength = 0;
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_decrypt(rsa, local_simple_random_function, rsa,
                                         MBEDTLS_RSA_PUBLIC, &outlength, cipher.bytes , buf, 300);
    if (ret_code) {
        NSLog(@"解密失败！！！ mbedtls 错误码为 %@ , 请检测公私钥是否匹配！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *plain = [NSData dataWithBytes:buf length:outlength];
    mbedtls_pk_free(&ctx);
    return plain;
}


+ (NSData *)decryptData:(NSData *)cipher usingPlulicKeyString:(NSString *)keyString {
    if (!cipher || !keyString) {
        NSLog(@"参数传入错误 ！！！");
        return nil;
    }
    if (cipher.length == 0) {
        NSLog(@"密文长度不能为空！！！");
        return nil;
    }
    if (keyString.length == 0) {
        NSLog(@"公钥字符串不正确 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_public_key(&ctx,(unsigned char *)keyString.UTF8String,keyString.length + 1);
    if (ret_code) {
        NSLog(@"公钥字符串读取失败， mbedtls错误码为 %@ , 请检测公钥字符串格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (cipher.length != rsa->len) {
        NSLog(@"公钥文件所指定的RSA加密位数为 %@ ,密文长度必须为 %@", @(rsa->len * 8) , @(rsa->len));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    size_t outlength = 0;
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_decrypt(rsa, local_simple_random_function, rsa,
                                         MBEDTLS_RSA_PUBLIC, &outlength, cipher.bytes , buf, 300);
    if (ret_code) {
        NSLog(@"解密失败！！！ mbedtls 错误码为 %@ , 请检测公私钥是否匹配！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *plain = [NSData dataWithBytes:buf length:outlength];
    mbedtls_pk_free(&ctx);
    return plain;
}

#pragma mark - 私钥

+ (NSData *)decryptData:(NSData *)cipher usingPrivateKeyFile:(NSString *)filepath {
    if (!cipher || !filepath) {
        NSLog(@"参数不能传入空值！！！");
        return nil;
    }
    if (cipher.length == 0) {
        NSLog(@"密文长度不能为空！！！");
        return nil;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:filepath]) {
        NSLog(@"私钥文件不存在 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_keyfile(&ctx,filepath.UTF8String,NULL);
    if (ret_code) {
        // 私钥文件格式需为 --BEGIN PRIVATE KEY--
        NSLog(@"私钥文件读取失败， mbedtls错误码为 %@ , 请检测私钥文件是否存在，或者私钥文件格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (cipher.length != rsa->len) {
        NSLog(@"私钥文件所指定的RSA加密位数为 %@ ,密文长度必须为 %@", @(rsa->len * 8) , @(rsa->len));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    size_t outlength = 0;
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_decrypt(rsa, local_simple_random_function, rsa,
                                         MBEDTLS_RSA_PRIVATE, &outlength, cipher.bytes , buf, 300);
    if (ret_code) {
        NSLog(@"解密失败！！！ mbedtls 错误码为 %@ , 请检测公私钥是否匹配！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *plain = [NSData dataWithBytes:buf length:outlength];
    mbedtls_pk_free(&ctx);
    return plain;
}

+ (NSData *)decryptData:(NSData *)cipher usingPrivateKeyString:(NSString *)keyString {
    if (!cipher || !keyString) {
        NSLog(@"参数不能传入空值！！！");
        return nil;
    }
    if (cipher.length == 0) {
        NSLog(@"密文长度不能为空！！！");
        return nil;
    }
    if (keyString.length == 0) {
        NSLog(@"私钥字符串不能为空 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_key(&ctx,(unsigned char *)keyString.UTF8String,keyString.length + 1,NULL,0);
    if (ret_code) {
        // 私钥格式需为 --BEGIN PRIVATE KEY--
        NSLog(@"私钥字符串读取失败， mbedtls错误码为 %@ , 请检测私钥字符串格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (cipher.length != rsa->len) {
        NSLog(@"私钥所指定的RSA加密位数为 %@ ,密文长度必须为 %@", @(rsa->len * 8) , @(rsa->len));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    size_t outlength = 0;
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_decrypt(rsa, local_simple_random_function, rsa,
                                         MBEDTLS_RSA_PRIVATE, &outlength, cipher.bytes , buf, 300);
    if (ret_code) {
        NSLog(@"解密失败！！！ mbedtls 错误码为 %@ , 请检测公私钥是否匹配！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *plain = [NSData dataWithBytes:buf length:outlength];
    mbedtls_pk_free(&ctx);
    return plain;
}

+ (NSData *)encryptData:(NSData *)plain usingPrivateKeyFile:(NSString *)filepath {
    if (!plain || !filepath) {
        NSLog(@"参数不能传入空值！！！");
        return nil;
    }
    if (plain.length == 0) {
        NSLog(@"明文长度不能为空！！！");
        return nil;
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:filepath]) {
        NSLog(@"私钥文件不存在 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_keyfile(&ctx,filepath.UTF8String,NULL);
    if (ret_code) {
        // 私钥文件格式需为 --BEGIN PRIVATE KEY--
        NSLog(@"私钥文件读取失败， mbedtls错误码为 %@ , 请检测私钥文件是否存在，或者私钥文件格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (plain.length + 11 > rsa->len) {
        NSLog(@"加密原文长度不能超过 %@ !!!",@(rsa->len - 11));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_encrypt( rsa, local_simple_random_function,
                                         rsa, MBEDTLS_RSA_PRIVATE,
                                         plain.length, plain.bytes, buf );
    if (ret_code) {
        NSLog(@"加密失败！！！ mbedtls 错误码为 %@ , 请检测私钥是否正确 ！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *cipher = [NSData dataWithBytes:buf length:rsa->len];
    mbedtls_pk_free(&ctx);
    return cipher;
}


+ (NSData *)encryptData:(NSData *)plain usingPrivateKeyString:(NSString *)keyString {
    if (!plain || !keyString) {
        NSLog(@"参数不能传入空值！！！");
        return nil;
    }
    if (plain.length == 0) {
        NSLog(@"明文长度不能为空！！！");
        return nil;
    }
    if (keyString.length == 0) {
        NSLog(@"私钥不能为空 ！！！");
        return nil;
    }
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret_code = mbedtls_pk_parse_key(&ctx,(unsigned char *)keyString.UTF8String,keyString.length + 1,NULL,0);
    if (ret_code) {
        // 私钥格式需为 --BEGIN PRIVATE KEY--
        NSLog(@"私钥字符串读取失败， mbedtls错误码为 %@ , 请检测私钥字符串格式是否正确！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx);
    if (plain.length + 11 > rsa->len) {
        NSLog(@"加密原文长度不能超过 %@ !!!",@(rsa->len - 11));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    unsigned char buf[300];
    ret_code = mbedtls_rsa_pkcs1_encrypt( rsa, local_simple_random_function,
                                         rsa, MBEDTLS_RSA_PRIVATE,
                                         plain.length, plain.bytes, buf );
    if (ret_code) {
        NSLog(@"加密失败！！！ mbedtls 错误码为 %@ , 请检测私钥是否正确 ！！！",@(ret_code));
        mbedtls_pk_free(&ctx);
        return nil;
    }
    NSData *cipher = [NSData dataWithBytes:buf length:rsa->len];
    mbedtls_pk_free(&ctx);
    return cipher;
}

#pragma mark - 密钥对生成
+ (BOOL)generatePrivateKey:(NSString **)privateKey PublicKey:(NSString **)publicKey byKeySize:(MXRSAKeySize)size {
    switch (size) {
        case MXRSAKeySize512:
        case MXRSAKeySize768:
        case MXRSAKeySize1024:
        case MXRSAKeySize2048:
            break;
        default:
            NSLog(@"请输入正确的 keySize, 请使用MXRSAKeySize枚举！！！");
            return NO;
            break;
    }
    if (privateKey == NULL || publicKey == NULL) {
        NSLog(@"参数不能为空！！！");
        return NO;
    }
    mbedtls_pk_context key;
    mbedtls_pk_init( &key );
    mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) );
    int ret = mbedtls_rsa_gen_key( mbedtls_pk_rsa( key ),local_simple_random_function , &key,
                                  size , 65537 );
    if (ret) {
        NSLog(@"公私钥生成失败，mbedtls 错误码为 %@" , @(ret));
        mbedtls_pk_free(&key);
        return NO;
    }
    unsigned char private_buf[2000];
    unsigned char public_buf[2000];
    ret = mbedtls_pk_write_key_pem( &key, private_buf, 2000 );
    if (ret) {
        NSLog(@"私钥输出失败， mbedtls错误码为 %@",@(ret));
        mbedtls_pk_free(&key);
        return NO;
    }
    ret = mbedtls_pk_write_pubkey_pem(&key, public_buf, 2000 );
    if (ret) {
        NSLog(@"公钥输出失败， mbedtls错误码为 %@",@(ret));
        mbedtls_pk_free(&key);
        return NO;
    }
    *privateKey = [[NSString alloc] initWithUTF8String:(char *)private_buf];
    *publicKey = [[NSString alloc] initWithUTF8String:(char *)public_buf];
    return YES;
}
@end
