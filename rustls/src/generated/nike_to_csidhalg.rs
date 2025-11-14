match scheme {
    SignatureScheme::NIKE_CTIDH512 => NikeImpl::CTIDH512,
    _ => unreachable!(),}