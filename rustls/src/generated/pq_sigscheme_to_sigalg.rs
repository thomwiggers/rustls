match self.scheme {
    SignatureScheme::DILITHIUM2 => SignatureAlgorithm::DILITHIUM2,
    SignatureScheme::XMSS1 => SignatureAlgorithm::XMSS1,
    SignatureScheme::XMSS3 => SignatureAlgorithm::XMSS3,
    SignatureScheme::XMSS5 => SignatureAlgorithm::XMSS5,
    _ => unreachable!(),}