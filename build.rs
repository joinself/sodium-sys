extern crate bindgen;

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

fn main() {
    let sodium_includes = Path::new("vendor/src/libsodium/include/sodium/");
    
    let version_header_data = "#ifndef sodium_version_H\n#define sodium_version_H\n#include \"export.h\"\n#define SODIUM_VERSION_STRING \"1.0.18\"\n\n#define SODIUM_LIBRARY_VERSION_MAJOR 10\n#define SODIUM_LIBRARY_VERSION_MINOR 3\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\nSODIUM_EXPORT\nconst char *sodium_version_string(void);\nSODIUM_EXPORT\nint         sodium_library_version_major(void);\nSODIUM_EXPORT\nint         sodium_library_version_minor(void);\nSODIUM_EXPORT\nint         sodium_library_minimal(void);\n\n#ifdef __cplusplus\n}\n#endif\n#endif";

    let mut version_header_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("vendor/src/libsodium/include/sodium/version.h")
        .unwrap();
        
    version_header_file
        .write(version_header_data.as_bytes())
        .unwrap();
        
    let mut cmd = cc::Build::new();
    
    cmd.warnings(false)
        .include(sodium_includes)
        .warnings(false)
        .file("vendor/src/libsodium/crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c")
        .file("vendor/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c")
        .file("vendor/src/libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c")
        .file("vendor/src/libsodium/crypto_auth/crypto_auth.c")
        .file("vendor/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256.c")
        .file("vendor/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c")
        .file("vendor/src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256.c")
        .file("vendor/src/libsodium/crypto_box/crypto_box_easy.c")
        .file("vendor/src/libsodium/crypto_box/crypto_box_seal.c")
        .file("vendor/src/libsodium/crypto_box/crypto_box.c")
        .file("vendor/src/libsodium/crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c")
        .file("vendor/src/libsodium/crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.c")
        .file("vendor/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c")
        .file("vendor/src/libsodium/crypto_core/ed25519/core_ed25519.c")
        .file("vendor/src/libsodium/crypto_core/ed25519/core_ristretto255.c")
        .file("vendor/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c")
        .file("vendor/src/libsodium/crypto_core/hchacha20/core_hchacha20.c")
        .file("vendor/src/libsodium/crypto_core/hsalsa20/core_hsalsa20.c")
        .file("vendor/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c")
        .file("vendor/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c")
        .file("vendor/src/libsodium/crypto_generichash/blake2b/generichash_blake2.c")
        .file("vendor/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-avx2.c")
        .file("vendor/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c")
        .file("vendor/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-sse41.c")
        .file("vendor/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c")
        .file("vendor/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c")
        .file("vendor/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c")
        .file("vendor/src/libsodium/crypto_generichash/crypto_generichash.c")
        .file("vendor/src/libsodium/crypto_hash/crypto_hash.c")
        .file("vendor/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c")
        .file("vendor/src/libsodium/crypto_hash/sha256/hash_sha256.c")
        .file("vendor/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c")
        .file("vendor/src/libsodium/crypto_hash/sha512/hash_sha512.c")
        .file("vendor/src/libsodium/crypto_kdf/blake2b/kdf_blake2b.c")
        .file("vendor/src/libsodium/crypto_kdf/crypto_kdf.c")
        .file("vendor/src/libsodium/crypto_kx/crypto_kx.c")
        .file("vendor/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c")
        .file("vendor/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c")
        .file("vendor/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c")
        .file("vendor/src/libsodium/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/argon2-core.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-avx2.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-avx512f.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ssse3.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/argon2.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/blake2b-long.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.c")
        .file("vendor/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c")
        .file("vendor/src/libsodium/crypto_pwhash/crypto_pwhash.c")
        .file("vendor/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c")
        .file("vendor/src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c")
        .file("vendor/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c")
        .file("vendor/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c")
        .file("vendor/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c")
        .file("vendor/src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c")
        .file("vendor/src/libsodium/crypto_scalarmult/crypto_scalarmult.c")
        .file("vendor/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c")
        .file("vendor/src/libsodium/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c")
        .file("vendor/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c")
        .file("vendor/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_invert.c")
        .file("vendor/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c")
        .file("vendor/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c")
        .file("vendor/src/libsodium/crypto_scalarmult/ristretto255/ref10/scalarmult_ristretto255_ref10.c")
        .file("vendor/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c")
        .file("vendor/src/libsodium/crypto_secretbox/crypto_secretbox.c")
        .file("vendor/src/libsodium/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c")
        .file("vendor/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c")
        .file("vendor/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c")
        .file("vendor/src/libsodium/crypto_shorthash/crypto_shorthash.c")
        .file("vendor/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c")
        .file("vendor/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c")
        .file("vendor/src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24.c")
        .file("vendor/src/libsodium/crypto_shorthash/siphash24/shorthash_siphashx24.c")
        .file("vendor/src/libsodium/crypto_sign/crypto_sign.c")
        .file("vendor/src/libsodium/crypto_sign/ed25519/ref10/keypair.c")
        .file("vendor/src/libsodium/crypto_sign/ed25519/ref10/obsolete.c")
        .file("vendor/src/libsodium/crypto_sign/ed25519/ref10/open.c")
        .file("vendor/src/libsodium/crypto_sign/ed25519/ref10/sign.c")
        .file("vendor/src/libsodium/crypto_sign/ed25519/sign_ed25519.c")
        .file("vendor/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c")
        .file("vendor/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c")
        .file("vendor/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c")
        .file("vendor/src/libsodium/crypto_stream/chacha20/stream_chacha20.c")
        .file("vendor/src/libsodium/crypto_stream/crypto_stream.c")
        .file("vendor/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c")
        .file("vendor/src/libsodium/crypto_stream/salsa20/stream_salsa20.c")
        .file("vendor/src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6.c")
        .file("vendor/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c")
        .file("vendor/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c")
        .file("vendor/src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012_ref.c")
        .file("vendor/src/libsodium/crypto_stream/salsa2012/stream_salsa2012.c")
        .file("vendor/src/libsodium/crypto_stream/salsa208/ref/stream_salsa208_ref.c")
        .file("vendor/src/libsodium/crypto_stream/salsa208/stream_salsa208.c")
        .file("vendor/src/libsodium/crypto_stream/xchacha20/stream_xchacha20.c")
        .file("vendor/src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20.c")
        .file("vendor/src/libsodium/crypto_verify/sodium/verify.c")
        .file("vendor/src/libsodium/randombytes/internal/randombytes_internal_random.c")
        .file("vendor/src/libsodium/randombytes/randombytes.c")
        .file("vendor/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c")
        .file("vendor/src/libsodium/sodium/codecs.c")
        .file("vendor/src/libsodium/sodium/core.c")
        .file("vendor/src/libsodium/sodium/runtime.c")
        .file("vendor/src/libsodium/sodium/utils.c")
        .file("vendor/src/libsodium/sodium/version.c");

    cmd.compile("sodium");

    // generate the bindings for sodium headers
    let builder = bindgen::Builder::default();
    let bindings = builder
        .clang_arg("-Ivendor/src/libsodium/include/")
        .clang_arg("-Ivendor/src/libsodium/include/sodium/")
        .allowlist_type(r"crypto.*")
        .allowlist_type(r"sodium.*")
        .allowlist_type(r"randombytes.*")
        .allowlist_function(r"crypto.*")
        .allowlist_function(r"sodium.*")
        .allowlist_function(r"randombytes.*")
        .allowlist_var(r"crypto.*")
        .allowlist_var(r"sodium.*")
        .allowlist_var(r"randombytes.*")
        .header("vendor/src/libsodium/include/sodium.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate sodium bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // output the bindings
    bindings
        .write_to_file(out_path.join("sodium.rs"))
        .expect("Couldn't write sodium bindings!");
}