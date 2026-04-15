
match scheme {
    ECDSA_NISTP256_SHA256 => Ok(&webpki::ECDSA_P256_SHA256),
    ECDSA_NISTP384_SHA384 => Ok(&webpki::ECDSA_P384_SHA384),
    ED25519 => Ok(&webpki::ED25519),
    RSA_PSS_SHA256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
    RSA_PSS_SHA384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
    RSA_PSS_SHA512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),    MLDSA44 => Ok(&webpki::MLDSA44),
    MLDSA65 => Ok(&webpki::MLDSA65),
    MLDSA87 => Ok(&webpki::MLDSA87),
    XMSS1 => Ok(&webpki::XMSS1),
    XMSS3 => Ok(&webpki::XMSS3),
    XMSS5 => Ok(&webpki::XMSS5),

    _ => {
        let error_msg = format!("received unsupported sig scheme {:?}", scheme);
        Err(TLSError::PeerMisbehavedError(error_msg))
    }
}