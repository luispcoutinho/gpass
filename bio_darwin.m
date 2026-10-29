#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#include <stdlib.h>
#include <string.h>
#include "bio_darwin.h"

int bio_available(void) {
	LAContext *ctx = [[LAContext alloc] init];
	NSError *err = nil;
	return [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err] ? 1 : 0;
}

int bio_authenticate(const char *reason) {
	LAContext *ctx = [[LAContext alloc] init];
	ctx.localizedFallbackTitle = @""; // hide the password button; we fall back to our own prompt
	__block int result = 2;
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
	    localizedReason:[NSString stringWithUTF8String:reason]
	              reply:^(BOOL ok, NSError *e) {
		if (ok) {
			result = 0;
		} else if (e.code == LAErrorUserCancel || e.code == LAErrorUserFallback ||
		           e.code == LAErrorSystemCancel || e.code == LAErrorAppCancel) {
			result = 1;
		}
		dispatch_semaphore_signal(sem);
	}];
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	return result;
}

static NSMutableDictionary *kc_query(const char *service, const char *account) {
	return [@{
		(id)kSecClass: (id)kSecClassGenericPassword,
		(id)kSecAttrService: [NSString stringWithUTF8String:service],
		(id)kSecAttrAccount: [NSString stringWithUTF8String:account],
	} mutableCopy];
}

int kc_set(const char *service, const char *account, const unsigned char *data, int len) {
	NSMutableDictionary *q = kc_query(service, account);
	SecItemDelete((__bridge CFDictionaryRef)q);
	q[(id)kSecValueData] = [NSData dataWithBytes:data length:len];
	return (int)SecItemAdd((__bridge CFDictionaryRef)q, NULL);
}

// Looks for the item without reading its secret, so it never triggers a keychain prompt.
int kc_exists(const char *service, const char *account) {
	NSMutableDictionary *q = kc_query(service, account);
	q[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
	return (int)SecItemCopyMatching((__bridge CFDictionaryRef)q, NULL);
}

int kc_get(const char *service, const char *account, unsigned char **out, int *len) {
	NSMutableDictionary *q = kc_query(service, account);
	q[(id)kSecReturnData] = @YES;
	q[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
	CFTypeRef res = NULL;
	OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
	if (st == errSecSuccess) {
		NSData *d = (__bridge_transfer NSData *)res;
		*len = (int)d.length;
		*out = malloc(d.length ? d.length : 1);
		memcpy(*out, d.bytes, d.length);
	}
	return (int)st;
}

void kc_free(unsigned char *buf, int len) {
	if (buf) {
		memset(buf, 0, len);
		free(buf);
	}
}

int kc_delete(const char *service, const char *account) {
	return (int)SecItemDelete((__bridge CFDictionaryRef)kc_query(service, account));
}
