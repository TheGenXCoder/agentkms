//go:build darwin

package keystore

// secureenclave_darwin.go — Apple Secure Enclave backend (macOS M1/M2/M3/T2).
//
// Private keys are generated inside the Secure Enclave Processor (SEP) and
// are NEVER extractable.  The key is bound to this device and this OS user.
// Signing operations are delegated to the SEP — the private key bytes never
// appear in process memory.
//
// Implementation:
//   - Uses Security.framework (CGo) to call SecKeyCreateRandomKey with
//     kSecAttrTokenIDSecureEnclave.
//   - The key is stored in the macOS Keychain with the label "agentkms-identity"
//     and the application tag "com.agentkms.identity".
//   - Subsequent Opens retrieve the key by label+tag using SecItemCopyMatching.
//   - Sign() calls SecKeyCreateSignature (ECDSA-SHA256) entirely within the SEP.

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// createSEKey creates a new P-256 key in the Secure Enclave using the modern API.
OSStatus createSEKey(const char *label) {
    CFStringRef keyLabel = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    CFDataRef   appTag   = CFDataCreate(NULL, (const UInt8 *)"com.agentkms.identity", 21);

    // Private key attributes — stored permanently in Keychain / Secure Enclave
    CFMutableDictionaryRef privAttrs = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(privAttrs, kSecAttrIsPermanent,    kCFBooleanTrue);
    CFDictionarySetValue(privAttrs, kSecAttrLabel,          keyLabel);
    CFDictionarySetValue(privAttrs, kSecAttrApplicationTag, appTag);

    // Key generation parameters
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFNumberRef keySize = CFNumberCreate(NULL, kCFNumberIntType, &(int){256});
    CFDictionarySetValue(params, kSecAttrKeyType,       kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, keySize);
    CFDictionarySetValue(params, kSecAttrTokenID,       kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(params, kSecPrivateKeyAttrs,   privAttrs);

    CFErrorRef err = NULL;
    SecKeyRef privKey = SecKeyCreateRandomKey(params, &err);

    CFRelease(keySize);
    CFRelease(privAttrs);
    CFRelease(params);
    CFRelease(appTag);
    CFRelease(keyLabel);

    if (privKey) {
        CFRelease(privKey);
        return errSecSuccess;
    }
    if (err) {
        CFIndex code = CFErrorGetCode(err);
        CFRelease(err);
        return (OSStatus)code;
    }
    return errSecInternalError;
}

// loadSEKey looks up the private key in the Keychain by label.
// Returns NULL if not found.  Caller must CFRelease the returned key.
SecKeyRef loadSEKey(const char *label) {
    CFStringRef keyLabel = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    CFDataRef   appTag   = CFDataCreate(NULL, (const UInt8 *)"com.agentkms.identity", 21);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass,              kSecClassKey);
    CFDictionarySetValue(query, kSecAttrKeyClass,       kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecAttrLabel,          keyLabel);
    CFDictionarySetValue(query, kSecAttrApplicationTag, appTag);
    CFDictionarySetValue(query, kSecReturnRef,          kCFBooleanTrue);
    CFDictionarySetValue(query, kSecAttrTokenID,        kSecAttrTokenIDSecureEnclave);

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&key);

    CFRelease(query);
    CFRelease(appTag);
    CFRelease(keyLabel);
    (void)status;
    return key; // NULL if not found
}

// getPublicKeyDER returns the DER-encoded public key for the given SecKeyRef.
// Returns NULL on failure. Caller must free the returned buffer.
unsigned char *getPublicKeyDER(SecKeyRef privKey, size_t *outLen) {
    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    if (!pubKey) return NULL;

    CFErrorRef err = NULL;
    CFDataRef data = SecKeyCopyExternalRepresentation(pubKey, &err);
    CFRelease(pubKey);
    if (!data) {
        if (err) CFRelease(err);
        return NULL;
    }
    // data is uncompressed EC point: 04 || x || y (65 bytes for P-256)
    // We need to wrap it in a SubjectPublicKeyInfo DER structure.
    // P-256 OID: 1.2.840.10045.2.1 (id-ecPublicKey)
    // namedCurve: 1.2.840.10045.3.1.7 (prime256v1)
    static const unsigned char spkiPrefix[] = {
        0x30, 0x59,                   // SEQUENCE
        0x30, 0x13,                   // SEQUENCE (algorithm)
        0x06, 0x07,                   // OID id-ecPublicKey
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08,                   // OID prime256v1
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00              // BIT STRING (65 bytes, 0 unused bits)
    };

    CFIndex pointLen = CFDataGetLength(data);
    size_t  totalLen = sizeof(spkiPrefix) + pointLen;
    unsigned char *buf = (unsigned char *)malloc(totalLen);
    if (!buf) { CFRelease(data); return NULL; }
    memcpy(buf, spkiPrefix, sizeof(spkiPrefix));
    memcpy(buf + sizeof(spkiPrefix), CFDataGetBytePtr(data), pointLen);
    CFRelease(data);
    *outLen = totalLen;
    return buf;
}

// signWithSEKey signs a SHA-256 digest using the Secure Enclave key.
// Returns the DER-encoded ECDSA signature, or NULL on failure.
// Caller must free the returned buffer.
unsigned char *signWithSEKey(SecKeyRef key, const unsigned char *digest, size_t digestLen, size_t *outLen) {
    CFDataRef digestData = CFDataCreate(NULL, digest, digestLen);
    CFErrorRef err = NULL;
    CFDataRef sig = SecKeyCreateSignature(key,
        kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
        digestData, &err);
    CFRelease(digestData);
    if (!sig) {
        if (err) CFRelease(err);
        return NULL;
    }
    CFIndex sigLen = CFDataGetLength(sig);
    unsigned char *buf = (unsigned char *)malloc(sigLen);
    if (buf) {
        memcpy(buf, CFDataGetBytePtr(sig), sigLen);
        *outLen = sigLen;
    }
    CFRelease(sig);
    return buf;
}

// deleteSEKey removes the key from the Keychain.
OSStatus deleteSEKey(const char *label) {
    CFStringRef keyLabel = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    CFDataRef   appTag   = CFDataCreate(NULL, (const UInt8 *)"com.agentkms.identity", 21);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass,              kSecClassKey);
    CFDictionarySetValue(query, kSecAttrLabel,          keyLabel);
    CFDictionarySetValue(query, kSecAttrApplicationTag, appTag);

    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    CFRelease(appTag);
    CFRelease(keyLabel);
    return status;
}
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// secureEnclaveStore implements KeyStore backed by the macOS Secure Enclave.
type secureEnclaveStore struct {
	label string
	key   C.SecKeyRef
}

// supportsSecureEnclave returns true if the Secure Enclave is available.
// On macOS, this is true for M1/M2/M3 and T2-equipped Intel Macs.
func supportsSecureEnclave() bool {
	label := C.CString("agentkms-probe")
	defer C.free(unsafe.Pointer(label))
	// Try to find any key; if the SEP is available this returns quickly.
	k := C.loadSEKey(label)
	if k != 0 {
		C.CFRelease(C.CFTypeRef(k))
	}
	// We check by attempting a generate + immediate delete.
	status := C.createSEKey(label)
	if status != 0 {
		return false
	}
	C.deleteSEKey(label)
	return true
}

func generateSecureEnclave(cfg Config) (KeyStore, error) {
	label := C.CString(cfg.KeyLabel)
	defer C.free(unsafe.Pointer(label))

	status := C.createSEKey(label)
	if status != 0 {
		return nil, fmt.Errorf("keystore: SecureEnclave: create key failed (OSStatus %d)", int(status))
	}

	key := C.loadSEKey(label)
	if key == 0 {
		return nil, errors.New("keystore: SecureEnclave: key created but not found in Keychain")
	}

	return &secureEnclaveStore{label: cfg.KeyLabel, key: key}, nil
}

func openSecureEnclave(cfg Config) (KeyStore, error) {
	label := C.CString(cfg.KeyLabel)
	defer C.free(unsafe.Pointer(label))

	key := C.loadSEKey(label)
	if key == 0 {
		return nil, ErrKeyNotFound
	}

	return &secureEnclaveStore{label: cfg.KeyLabel, key: key}, nil
}

func (s *secureEnclaveStore) Backend() Backend { return BackendSecureEnclave }

func (s *secureEnclaveStore) Close() error {
	if s.key != 0 {
		C.CFRelease(C.CFTypeRef(s.key))
		s.key = 0
	}
	return nil
}

func (s *secureEnclaveStore) PublicKey() (crypto.PublicKey, error) {
	var outLen C.size_t
	buf := C.getPublicKeyDER(s.key, &outLen)
	if buf == nil {
		return nil, errors.New("keystore: SecureEnclave: failed to export public key")
	}
	defer C.free(unsafe.Pointer(buf))

	der := C.GoBytes(unsafe.Pointer(buf), C.int(outLen))
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("keystore: SecureEnclave: parse public key: %w", err)
	}
	return pub, nil
}

func (s *secureEnclaveStore) Signer() (crypto.Signer, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("keystore: SecureEnclave: expected ECDSA public key")
	}
	return &seSigner{store: s, pub: ecPub}, nil
}

// seSigner implements crypto.Signer by delegating to the Secure Enclave.
type seSigner struct {
	store *secureEnclaveStore
	pub   *ecdsa.PublicKey
}

func (s *seSigner) Public() crypto.PublicKey { return s.pub }

func (s *seSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("keystore: SecureEnclave: empty digest")
	}

	digestPtr := (*C.uchar)(unsafe.Pointer(&digest[0]))
	var outLen C.size_t

	sig := C.signWithSEKey(s.store.key, digestPtr, C.size_t(len(digest)), &outLen)
	if sig == nil {
		return nil, errors.New("keystore: SecureEnclave: signing failed")
	}
	defer C.free(unsafe.Pointer(sig))

	return C.GoBytes(unsafe.Pointer(sig), C.int(outLen)), nil
}
