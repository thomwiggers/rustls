match self.scheme {
    SignatureScheme::MLDSA44 => SignatureAlgorithm::MLDSA44,
    SignatureScheme::MLDSA65 => SignatureAlgorithm::MLDSA65,
    SignatureScheme::MLDSA87 => SignatureAlgorithm::MLDSA87,
    SignatureScheme::XMSS1 => SignatureAlgorithm::XMSS1,
    SignatureScheme::XMSS3 => SignatureAlgorithm::XMSS3,
    SignatureScheme::XMSS5 => SignatureAlgorithm::XMSS5,
    _ => unreachable!(),}