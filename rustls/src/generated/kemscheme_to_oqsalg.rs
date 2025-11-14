match scheme {
    SignatureScheme::KEMTLS_MLKEM512 => oqs::kem::Algorithm::MlKem512,
    SignatureScheme::KEMTLS_MLKEM768 => oqs::kem::Algorithm::MlKem768,
    SignatureScheme::KEMTLS_MLKEM1024 => oqs::kem::Algorithm::MlKem1024,
    _ => unreachable!(),}