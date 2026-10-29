#ifndef BIO_DARWIN_H
#define BIO_DARWIN_H

int bio_available(void);
// 0 = authenticated, 1 = cancelled by user, 2 = failed/unavailable
int bio_authenticate(const char *reason);

// Keychain helpers return an OSStatus (0 = success, -25300 = not found).
int kc_set(const char *service, const char *account, const unsigned char *data, int len);
int kc_exists(const char *service, const char *account);
int kc_get(const char *service, const char *account, unsigned char **out, int *len);
void kc_free(unsigned char *buf, int len);
int kc_delete(const char *service, const char *account);

#endif
