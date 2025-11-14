match group {

        NamedGroup::MlKem512 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::MlKem768 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::MlKem1024 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CTIDH512 => {
            Some(KexAlgorithm::CSIDH(NikeImpl::CTIDH512))
        },
_ => None,
}