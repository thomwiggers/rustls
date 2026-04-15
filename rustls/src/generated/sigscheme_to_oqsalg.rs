match scheme {
    SignatureScheme::MLDSA44 => oqs::sig::Algorithm::MlDsa44,
    SignatureScheme::MLDSA65 => oqs::sig::Algorithm::MlDsa65,
    SignatureScheme::MLDSA87 => oqs::sig::Algorithm::MlDsa87,
    _ => unreachable!(),}