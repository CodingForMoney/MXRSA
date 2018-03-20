//
//  ViewController.m
//  Example
//
//  Created by 罗贤明 on 2018/2/24.
//  Copyright © 2018年 罗贤明. All rights reserved.
//

#import "ViewController.h"
#import "MXRSA.h"
@interface ViewController ()

@end

// 注意，第一行必须有一个换行符！！！
static NSString *const PublicKey = @"-----BEGIN PUBLIC KEY-----\r\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxdwcxXxhCf5cWgkXYLI5+hyXg\
p+1SMuKh98r2lWnIPHeCAX+Hr40mKhmBiXsgyRH9RLlDchP2FtnWm6JbicPUkgfv\
ihqiwbrALKHB88zIfQL/FcQTGCt+N5xuYgT+v3bsVn0ktIL6J8Qh7F3O4Q21uVye\
r6tpY2z3RLYOZwKPMwIDAQAB\
-----END PUBLIC KEY-----";

static NSString *const PrivateKey = @"-----BEGIN PRIVATE KEY-----\r\n\
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPF3BzFfGEJ/lxaC\
Rdgsjn6HJeCn7VIy4qH3yvaVacg8d4IBf4evjSYqGYGJeyDJEf1EuUNyE/YW2dab\
oluJw9SSB++KGqLBusAsocHzzMh9Av8VxBMYK343nG5iBP6/duxWfSS0gvonxCHs\
Xc7hDbW5XJ6vq2ljbPdEtg5nAo8zAgMBAAECgYEA0H1Q1Z1hahGW2FWVjwkx5Cg3\
WVpFvOK48tbtBaqPEti666L1hafbvSc+rK2ThgR3JvMO8CBxAdxLLVVmg5lZXuVU\
tpbFxFvt3NX8685LdPv9D6JZh/qHA4o+fLp6aic++0NcerOXZJlTLmtud/l5xXRT\
G6xL6LU2TKC4p/4wddkCQQD/MQEBpsbTV4j/VIfDkeOBsqSY18NdMCcoEt3d/tVU\
FDYRbv0jx10hwZCW42Cs6yA5+9kQooGbUhp5VMdKSTSdAkEA8jrj29LqvVnQ0mys\
svfY79BLSjxA8hfhuZFJgKYE7iyNhBSVN8pbM1B+sTUgGM+tZcBh4OygNPBehAfU\
lUhCDwJBAMe8NDx1q8M5DUpDgCurYTVffIMAxbGHge5UrgEWdyRi2VrV0x4Q6a0F\
EsV23HEba1LW8zOY7faC0aPLnlxfZeUCQF/1KFLq6Qb9z5Wsa3WybYQC9fCAkhHV\
mBwVDBMksYtQpvcN2FbzmNFpL+cvbnmlu8E1RxD9bDHMjwSqvXIt380CQEMsBJEw\
jpTH29HsDmHOokmat7o94jDcFVoaWeRwGJFxbpbGzgXLLMijGxyfl6OW85sa6tCZ\
i+ZxICxKxOQcxjc=\
-----END PRIVATE KEY-----";

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    
    NSData *input = [@"hello world !!!" dataUsingEncoding:NSUTF8StringEncoding];
    NSString *private = [[NSBundle mainBundle] pathForResource:@"pri.pem" ofType:nil];
    NSString *public = [[NSBundle mainBundle] pathForResource:@"pub.pem" ofType:nil];
    NSData *cipher;
    NSData *plain;
    
    int64_t s = [[NSDate date] timeIntervalSince1970] * 1000;
    
    for (NSInteger i = 0; i < 10; i ++) {
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
    }
    int64_t e = [[NSDate date] timeIntervalSince1970] * 1000;
    NSLog(@"最终耗时位 ：%@", @(e - s));
    
    
    NSString *publicStr;
    NSString *privateStr;
    [MXRSA generatePrivateKey:&privateStr PublicKey:&publicStr byKeySize:MXRSAKeySize1024];
    cipher = [MXRSA encryptData:input usingPrivateKeyString:privateStr];
    plain = [MXRSA decryptData:cipher usingPlulicKeyString:publicStr];
    NSLog(@"%@",[[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding]);
    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
