match scheme {
    SignatureScheme::DILITHIUM2 => oqs::sig::Algorithm::Dilithium2,
    _ => unreachable!(),}