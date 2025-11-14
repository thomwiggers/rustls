match (named_group, sigalg) {
	(NamedGroup::CTIDH512, SignatureScheme::NIKE_CTIDH512) => true,
	(_, _) => false,}