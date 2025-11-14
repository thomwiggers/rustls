use crate::cipher;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{CipherSuite, HashAlgorithm, SignatureAlgorithm, SignatureScheme};
use crate::msgs::enums::{NamedGroup, ProtocolVersion};
use crate::msgs::handshake::DecomposedSignatureScheme;
use crate::msgs::handshake::KeyExchangeAlgorithm;
use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};

use oqs;

use ring;
use std::fmt;
use std::vec;

use crate::sign::NikeImpl;

pub enum KexAlgorithm {
    RingAlg(&'static ring::agreement::Algorithm),
    KEM(oqs::kem::Kem),
    CSIDH(NikeImpl),
    Hybrid(&'static ring::agreement::Algorithm, oqs::kem::Kem),
}

impl PartialEq for KexAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::RingAlg(l0), Self::RingAlg(r0)) => l0 == r0,
            (Self::KEM(l0), Self::KEM(r0)) => l0.algorithm() == r0.algorithm(),
            (Self::Hybrid(l0, l1), Self::Hybrid(r0, r1)) => {
                l0 == r0 && l1.algorithm() == r1.algorithm()
            }
            (Self::CSIDH(l0), Self::CSIDH(r0)) => l0 == r0,
            (_, _) => false,
        }
    }
}

impl Eq for KexAlgorithm {}

impl std::hash::Hash for KexAlgorithm {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            KexAlgorithm::RingAlg(_) => panic!("Not supported for ring algs"),
            KexAlgorithm::KEM(kem) => {
                "kem".hash(state);
                kem.algorithm().hash(state);
            }
            KexAlgorithm::Hybrid(_, _) => panic!("Not supported for hybrid"),
            KexAlgorithm::CSIDH(alg) => {
                "csidh".hash(state);
                match alg {
                    NikeImpl::SecSidh(alg) => alg.hash(state),
                    NikeImpl::CTIDH512 => "ctidh512".hash(state),
                    NikeImpl::CTIDH1024 => "ctidh1024".hash(state),
                }
            }
        }
    }
}

pub enum KexPrivateKey {
    RingKey(Option<ring::agreement::EphemeralPrivateKey>),
    KEM(oqs::kem::SecretKey),
    Hybrid(
        Option<ring::agreement::EphemeralPrivateKey>,
        oqs::kem::SecretKey,
    ),
    SECSIDH(secsidh::SecretKey),
    CTIDH512(csidh_rust::ctidh512::CSIDHPrivateKey),
    CTIDH1024(csidh_rust::ctidh1024::CSIDHPrivateKey),
}

impl Clone for KexPrivateKey {
    fn clone(&self) -> Self {
        match self {
            Self::RingKey(_) => panic!("Not supported for ECDH"),
            Self::KEM(arg0) => Self::KEM(arg0.clone()),
            Self::Hybrid(_, _) => panic!("Not supported for hybrid"),
            Self::SECSIDH(arg0) => Self::SECSIDH(arg0.clone()),
            Self::CTIDH512(arg0) => Self::CTIDH512(arg0.clone()),
            Self::CTIDH1024(arg0) => Self::CTIDH1024(arg0.clone()),
        }
    }
}

impl KexPrivateKey {
    fn take_ring_key(&mut self) -> ring::agreement::EphemeralPrivateKey {
        match self {
            Self::RingKey(key) => key.take().unwrap(),
            Self::Hybrid(key, _) => key.take().unwrap(),
            _ => panic!("Wrong key type"),
        }
    }
    fn as_kem_key(&self) -> &oqs::kem::SecretKey {
        match self {
            Self::Hybrid(_, key) => key,
            Self::KEM(key) => key,
            _ => panic!("Wrong key type!"),
        }
    }
    fn as_secsidh_key(&self) -> &secsidh::SecretKey {
        match self {
            Self::SECSIDH(key) => key,
            _ => panic!("Wrong key type!"),
        }
    }
}

#[derive(Clone)]
pub enum KexPublicKey {
    RingKey(ring::agreement::PublicKey),
    KEM(oqs::kem::PublicKey),
    Hybrid(vec::Vec<u8>),
    SECSIDH(secsidh::PublicKey),
    CTIDH512(csidh_rust::ctidh512::PublicKey),
    CTIDH1024(csidh_rust::ctidh1024::PublicKey),
}

// impl KexPublicKey {
//     fn into_ring_key(self) -> ring::agreement::PublicKey {
//         match self {
//             Self::RingKey(key) => key,
//             _ => panic!("Wrong key type"),
//         }
//     }
// }

impl AsRef<[u8]> for KexPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::RingKey(key) => key.as_ref(),
            Self::KEM(key) => key.as_ref(),
            Self::Hybrid(key) => key.as_ref(),
            Self::SECSIDH(key) => key.as_ref(),
            Self::CTIDH512(key) => key.as_ref(),
            Self::CTIDH1024(key) => key.as_ref(),
        }
    }
}

/// Bulk symmetric encryption scheme used by a cipher suite.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum BulkAlgorithm {
    /// AES with 128-bit keys in Galois counter mode.
    AES_128_GCM,

    /// AES with 256-bit keys in Galois counter mode.
    AES_256_GCM,

    /// Chacha20 for confidentiality with poly1305 for authenticity.
    CHACHA20_POLY1305,
}

/// The result of a key exchange.  This has our public key,
/// and the agreed shared secret (also known as the "premaster secret"
/// in TLS1.0-era protocols, and "Z" in TLS1.3).
pub struct KeyExchangeResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
pub struct KeyExchange {
    pub group: NamedGroup,
    alg: KexAlgorithm,
    privkey: KexPrivateKey,
    pub pubkey: KexPublicKey,
}

#[cfg(feature = "lru")]
use lazy_static::lazy_static;
#[cfg(feature = "lru")]
use lru::LruCache;
#[cfg(feature = "lru")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "lru")]
lazy_static! {
    static ref CACHE: Arc<Mutex<LruCache<NamedGroup, (KexPublicKey, KexPrivateKey)>>> =
        Arc::new(Mutex::new(LruCache::unbounded()));
}

impl KeyExchange {
    pub fn named_group_to_ecdh_alg(group: NamedGroup) -> Option<KexAlgorithm> {
        match group {
            NamedGroup::X25519 => Some(KexAlgorithm::RingAlg(&ring::agreement::X25519)),
            NamedGroup::secp256r1 => Some(KexAlgorithm::RingAlg(&ring::agreement::ECDH_P256)),
            NamedGroup::secp384r1 => Some(KexAlgorithm::RingAlg(&ring::agreement::ECDH_P384)),
            NamedGroup::secp256r1MLKEM768 => {
                oqs::init();
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).unwrap();
                Some(KexAlgorithm::Hybrid(&ring::agreement::ECDH_P256, kem))
            }
            NamedGroup::X25519MLKEM768 => {
                oqs::init();
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).unwrap();
                Some(KexAlgorithm::Hybrid(&ring::agreement::X25519, kem))
            }
            NamedGroup::secp384r1MLKEM1024 => {
                oqs::init();
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).unwrap();
                Some(KexAlgorithm::Hybrid(&ring::agreement::ECDH_P384, kem))
            }
            group => include!("generated/named_group_to_kex.rs"),
        }
    }

    pub fn supported_groups() -> &'static [NamedGroup] {
        // in preference order
        include!("generated/supported_kex_groups.rs")
        // &[
        //     NamedGroup::X25519,
        //     NamedGroup::secp384r1,
        //     NamedGroup::secp256r1,
        // ]
    }

    pub fn supported_groups_tls12() -> &'static [NamedGroup] {
        // in preference order
        &[
            NamedGroup::X25519,
            NamedGroup::secp384r1,
            NamedGroup::secp256r1,
        ]
    }

    #[allow(unused_variables)]
    fn generate_key(group: NamedGroup, alg: &KexAlgorithm) -> (KexPublicKey, KexPrivateKey) {
        #[cfg(feature = "lru")]
        {
            let mutex = Arc::clone(&CACHE);
            let mut cache = mutex.lock().unwrap();
            if let Some(result) = cache.peek(&group) {
                return result.clone();
            }
        }

        let result = match alg {
            KexAlgorithm::KEM(kem) => {
                let (pk, sk) = kem.keypair().unwrap();
                (KexPublicKey::KEM(pk), KexPrivateKey::KEM(sk))
            }
            KexAlgorithm::Hybrid(ecdh, kem) => {
                let rng = ring::rand::SystemRandom::new();
                let ours = ring::agreement::EphemeralPrivateKey::generate(*ecdh, &rng).unwrap();

                let ecdhpubkey = ours.compute_public_key().unwrap();
                let (kempk, kemsk) = kem.keypair().unwrap();
                let mut pubkeyvec = ecdhpubkey.as_ref().to_vec();
                pubkeyvec.extend_from_slice(kempk.as_ref());
                (
                    KexPublicKey::Hybrid(pubkeyvec),
                    KexPrivateKey::Hybrid(Some(ours), kemsk),
                )
            }
            KexAlgorithm::CSIDH(alg) => match alg {
                NikeImpl::SecSidh(alg) => {
                    let (pk, sk) = secsidh::keygen(*alg).unwrap();
                    (KexPublicKey::SECSIDH(pk), KexPrivateKey::SECSIDH(sk))
                }
                NikeImpl::CTIDH512 => {
                    let (pk, sk) = csidh_rust::ctidh512::keypair();
                    (KexPublicKey::CTIDH512(pk), KexPrivateKey::CTIDH512(sk))
                }
                NikeImpl::CTIDH1024 => {
                    let (pk, sk) = csidh_rust::ctidh1024::keypair();
                    (KexPublicKey::CTIDH1024(pk), KexPrivateKey::CTIDH1024(sk))
                }
            },
            _ => unreachable!("Should already be covered"),
        };
        #[cfg(feature = "lru")]
        {
            let mutex = Arc::clone(&CACHE);
            let mut cache = mutex.lock().unwrap();
            cache.put(group, result.clone());
        }
        result
    }

    // Generate's the public key keyshare
    pub fn start_kex(named_group: NamedGroup) -> Option<KeyExchange> {
        let alg = KeyExchange::named_group_to_ecdh_alg(named_group)?;
        match alg {
            KexAlgorithm::RingAlg(alg) => Self::start_ecdhe(named_group, alg),
            _ => {
                let (pubkey, privkey) = KeyExchange::generate_key(named_group, &alg);
                Some(KeyExchange {
                    group: named_group,
                    alg: alg,
                    privkey,
                    pubkey,
                })
            }
        }
    }

    // Encapsulates to the server's share
    pub fn encapsulate(named_group: NamedGroup, peer: &[u8]) -> Option<KeyExchangeResult> {
        let alg = KeyExchange::named_group_to_ecdh_alg(named_group)?;
        match alg {
            KexAlgorithm::RingAlg(alg) => {
                let mut kex = Self::start_ecdhe(named_group, alg)?;
                let ciphertext = kex.pubkey.as_ref().to_vec();
                let shared_secret = kex.decapsulate(peer)?;
                Some(KeyExchangeResult {
                    ciphertext,
                    shared_secret,
                })
            }
            KexAlgorithm::KEM(kem) => {
                let pk = kem.public_key_from_bytes(peer)?;
                let (ciphertext, shared_secret) = kem.encapsulate(pk).ok()?;
                Some(KeyExchangeResult {
                    ciphertext: ciphertext.into_vec(),
                    shared_secret: shared_secret.into_vec(),
                })
            }
            KexAlgorithm::Hybrid(alg, kem) => {
                let mut kex = Self::start_ecdhe(named_group, alg)?;
                let ecdh_ciphertext = kex.pubkey.as_ref().to_vec();
                let len = kex.pubkey.as_ref().len();
                let ecdh_shared_secret = kex.decapsulate(peer[..len].as_ref())?;
                let pk = kem.public_key_from_bytes(peer[len..].as_ref())?;
                let (kem_ciphertext, kem_shared_secret) = kem.encapsulate(pk).ok()?;
                let mut ciphertext = ecdh_ciphertext;
                ciphertext.append(&mut kem_ciphertext.into_vec());
                let mut shared_secret = ecdh_shared_secret;
                shared_secret.append(&mut kem_shared_secret.into_vec());
                Some(KeyExchangeResult {
                    ciphertext,
                    shared_secret,
                })
            }
            KexAlgorithm::CSIDH(csidhalg) => {
                // our public key is the ciphertext if we phrase a NIKE as a KEM
                let (pubkey, privkey) = KeyExchange::generate_key(named_group, &alg);
                let (ciphertext, shared_secret) = match csidhalg {
                    NikeImpl::CTIDH512 => {
                        let sk = match privkey {
                            KexPrivateKey::CTIDH512(sk) => sk,
                            _ => unreachable!(),
                        };
                        let ciphertext = pubkey.as_ref().to_vec();
                        let pk_b = csidh_rust::ctidh512::CSIDHPublicKey::from_bytes(peer);
                        let shared_secret = csidh_rust::ctidh512::agreement(&pk_b, &sk);
                        (ciphertext, shared_secret.to_vec())
                    }
                    NikeImpl::CTIDH1024 => {
                        let sk = match privkey {
                            KexPrivateKey::CTIDH1024(sk) => sk,
                            _ => unreachable!(),
                        };
                        let ciphertext = pubkey.as_ref().to_vec();
                        let pk_b = csidh_rust::ctidh1024::CSIDHPublicKey::from_bytes(peer);
                        let shared_secret = csidh_rust::ctidh1024::agreement(&pk_b, &sk);
                        (ciphertext, shared_secret.to_vec())
                    }
                    NikeImpl::SecSidh(secsidhalg) => {
                        let sk = privkey.as_secsidh_key();
                        let ciphertext = pubkey.as_ref().to_vec();
                        let pk_b = secsidh::PublicKey::from_bytes(secsidhalg, peer)?;
                        let shared_secret = secsidh::derive(&pk_b, &sk)?;
                        (ciphertext, shared_secret)
                    }
                };

                Some(KeyExchangeResult {
                    ciphertext,
                    shared_secret,
                })
            }
        }
    }

    fn start_ecdhe(
        named_group: NamedGroup,
        alg: &'static ring::agreement::Algorithm,
    ) -> Option<KeyExchange> {
        let rng = ring::rand::SystemRandom::new();
        let ours = ring::agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap();

        let pubkey = ours.compute_public_key().unwrap();

        Some(KeyExchange {
            group: named_group,
            alg: KexAlgorithm::RingAlg(&alg),
            privkey: KexPrivateKey::RingKey(Some(ours)),
            pubkey: KexPublicKey::RingKey(pubkey),
        })
    }

    pub fn check_client_params(&self, kx_params: &[u8]) -> bool {
        self.decode_client_params(kx_params)
            .is_some()
    }

    fn decode_client_params(&self, kx_params: &[u8]) -> Option<ClientECDHParams> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = ClientECDHParams::read(&mut rd).unwrap();
        if rd.any_left() {
            None
        } else {
            Some(ecdh_params)
        }
    }

    pub fn client_kex(kx_params: &[u8]) -> Option<KeyExchangeResult> {
        let mut rd = Reader::init(kx_params);
        let server_params = ServerECDHParams::read(&mut rd).unwrap();

        Self::encapsulate(
            server_params.curve_params.named_group,
            &server_params.public.0,
        )
    }

    pub fn server_decapsulate(mut self, kx_params: &[u8]) -> Option<Vec<u8>> {
        self.decode_client_params(kx_params)
            .and_then(|ecdh| self.decapsulate(&ecdh.public.0))
    }

    pub fn decapsulate(&mut self, peer: &[u8]) -> Option<Vec<u8>> {
        match &self.alg {
            KexAlgorithm::RingAlg(alg) => {
                let peer_key = ring::agreement::UnparsedPublicKey::new(alg, peer);
                let secret = ring::agreement::agree_ephemeral(
                    self.privkey.take_ring_key(),
                    &peer_key,
                    (),
                    |v| {
                        let mut r = Vec::new();
                        r.extend_from_slice(v);
                        Ok(r)
                    },
                );

                if secret.is_err() {
                    return None;
                }

                Some(secret.unwrap())
            }
            KexAlgorithm::KEM(kem) => {
                let sk = self.privkey.as_kem_key();
                let ct = kem.ciphertext_from_bytes(&peer)?;
                Some(kem.decapsulate(sk, ct).ok()?.into_vec())
            }
            KexAlgorithm::Hybrid(alg, kem) => {
                let hybrid_len = if *alg == &ring::agreement::X25519 {
                    32
                } else if *alg == &ring::agreement::ECDH_P256 {
                    64
                } else if *alg == &ring::agreement::ECDH_P384 {
                    96
                } else {
                    unreachable!()
                };

                let peer_key = ring::agreement::UnparsedPublicKey::new(alg, &peer[..hybrid_len]);
                let ct = kem.ciphertext_from_bytes(&peer[hybrid_len..])?;
                let secret = ring::agreement::agree_ephemeral(
                    self.privkey.take_ring_key(),
                    &peer_key,
                    (),
                    |v| {
                        let sk = self.privkey.as_kem_key();
                        let kemss = kem
                            .decapsulate(sk, ct)
                            .unwrap();
                        let mut r = Vec::with_capacity(v.len() + kemss.len());
                        r.extend_from_slice(v);
                        r.extend_from_slice(kemss.as_ref());
                        Ok(r)
                    },
                );

                if secret.is_err() {
                    return None;
                }

                Some(secret.unwrap())
            }
            KexAlgorithm::CSIDH(alg) => match alg {
                NikeImpl::CTIDH512 => {
                    let sk = match self.privkey {
                        KexPrivateKey::CTIDH512(sk) => sk,
                        _ => unreachable!(),
                    };
                    let pk_b = csidh_rust::ctidh512::CSIDHPublicKey::from_bytes(peer);
                    Some(csidh_rust::ctidh512::agreement(&pk_b, &sk).to_vec())
                }
                NikeImpl::CTIDH1024 => {
                    let sk = match self.privkey {
                        KexPrivateKey::CTIDH1024(sk) => sk,
                        _ => unreachable!(),
                    };
                    let pk_b = csidh_rust::ctidh1024::CSIDHPublicKey::from_bytes(peer);
                    Some(csidh_rust::ctidh1024::agreement(&pk_b, &sk).to_vec())
                }
                NikeImpl::SecSidh(alg) => {
                    let sk = self.privkey.as_secsidh_key();
                    let pk_b = secsidh::PublicKey::from_bytes(*alg, peer)?;
                    secsidh::derive(&pk_b, &sk)
                }
            },
        }
    }
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_CIPHERSUITES` array.
pub struct SupportedCipherSuite {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to do bulk encryption.
    pub bulk: BulkAlgorithm,

    /// How to do hashing.
    pub hash: HashAlgorithm,

    /// How to sign messages for authentication.
    ///
    /// This is not present for TLS1.3, because authentication is orthogonal
    /// to the ciphersuite concept there.
    pub sign: Option<&'static [SignatureScheme]>,

    /// Encryption key length, for the bulk algorithm.
    pub enc_key_len: usize,

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,

    pub(crate) hkdf_algorithm: ring::hkdf::Algorithm,
    pub(crate) aead_algorithm: &'static ring::aead::Algorithm,
    pub(crate) build_tls12_encrypter: Option<cipher::BuildTLS12Encrypter>,
    pub(crate) build_tls12_decrypter: Option<cipher::BuildTLS12Decrypter>,
}

impl PartialEq for SupportedCipherSuite {
    fn eq(&self, other: &SupportedCipherSuite) -> bool {
        self.suite == other.suite
    }
}

impl fmt::Debug for SupportedCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupportedCipherSuite")
            .field("suite", &self.suite)
            .field("kx", &self.kx)
            .field("bulk", &self.bulk)
            .field("hash", &self.hash)
            .field("sign", &self.sign)
            .field("enc_key_len", &self.enc_key_len)
            .field("fixed_iv_len", &self.fixed_iv_len)
            .field("explicit_nonce_len", &self.explicit_nonce_len)
            .finish()
    }
}

impl SupportedCipherSuite {
    /// Which hash function to use with this suite.
    pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
        self.hkdf_algorithm
            .hmac_algorithm()
            .digest_algorithm()
    }

    /// We have parameters and a verified public key in `kx_params`.
    /// Generate an ephemeral key, generate the shared secret, and
    /// return it and the public half in a `KeyExchangeResult`.
    pub fn do_client_kx(&self, kx_params: &[u8]) -> Option<KeyExchangeResult> {
        match self.kx {
            KeyExchangeAlgorithm::ECDHE => KeyExchange::client_kex(kx_params),
            _ => None,
        }
    }

    /// Start the KX process with the given group.  This generates
    /// the server's share, but we don't yet have the client's share.
    /// Not used in TLS 1.3
    pub fn start_server_kx(&self, named_group: NamedGroup) -> Option<KeyExchange> {
        match self.kx {
            KeyExchangeAlgorithm::ECDHE => KeyExchange::start_kex(named_group),
            _ => None,
        }
    }

    /// Resolve the set of supported `SignatureScheme`s from the
    /// offered `SupportedSignatureSchemes`.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        if let Some(our_preference) = self.sign {
            our_preference
                .iter()
                .filter(|pref| offered.contains(pref))
                .cloned()
                .collect()
        } else {
            vec![]
        }
    }

    /// Length of key block that needs to be output by the key
    /// derivation phase for this suite.
    pub fn key_block_len(&self) -> usize {
        (self.enc_key_len + self.fixed_iv_len) * 2 + self.explicit_nonce_len
    }

    /// Return true if this suite is usable for TLS `version`.
    pub fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_3 => self.build_tls12_encrypter.is_none(),
            ProtocolVersion::TLSv1_2 => self.build_tls12_encrypter.is_some(),
            _ => false,
        }
    }

    /// Return true if this suite is usable for a key only offering `sigalg`
    /// signatures.  This resolves to true for all TLS1.3 suites.
    pub fn usable_for_sigalg(&self, sigalg: SignatureAlgorithm) -> bool {
        match self.sign {
            None => true, // no constraint expressed by ciphersuite (eg, TLS1.3)
            Some(schemes) => schemes
                .iter()
                .any(|scheme| scheme.sign() == sigalg),
        }
    }

    /// Can a session using suite self resume using suite new_suite?
    pub fn can_resume_to(&self, new_suite: &SupportedCipherSuite) -> bool {
        if self.usable_for_version(ProtocolVersion::TLSv1_3)
            && new_suite.usable_for_version(ProtocolVersion::TLSv1_3)
        {
            // TLS1.3 actually specifies requirements here: suites are compatible
            // for resumption if they have the same KDF hash
            self.hash == new_suite.hash
        } else if self.usable_for_version(ProtocolVersion::TLSv1_2)
            && new_suite.usable_for_version(ProtocolVersion::TLSv1_2)
        {
            // Previous versions don't specify any constraint, so we don't
            // resume between suites to avoid bad interactions.
            self.suite == new_suite.suite
        } else {
            // Suites for different versions definitely can't resume!
            false
        }
    }
}

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: Some(TLS12_ECDSA_SCHEMES),
        bulk: BulkAlgorithm::CHACHA20_POLY1305,
        hash: HashAlgorithm::SHA256,
        enc_key_len: 32,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hkdf_algorithm: ring::hkdf::HKDF_SHA256,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
        build_tls12_encrypter: Some(cipher::build_tls12_chacha_encrypter),
        build_tls12_decrypter: Some(cipher::build_tls12_chacha_decrypter),
    };

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: Some(TLS12_RSA_SCHEMES),
        bulk: BulkAlgorithm::CHACHA20_POLY1305,
        hash: HashAlgorithm::SHA256,
        enc_key_len: 32,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hkdf_algorithm: ring::hkdf::HKDF_SHA256,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
        build_tls12_encrypter: Some(cipher::build_tls12_chacha_encrypter),
        build_tls12_decrypter: Some(cipher::build_tls12_chacha_decrypter),
    };

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: Some(TLS12_RSA_SCHEMES),
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::AES_128_GCM,
    build_tls12_encrypter: Some(cipher::build_tls12_gcm_128_encrypter),
    build_tls12_decrypter: Some(cipher::build_tls12_gcm_128_decrypter),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: Some(TLS12_RSA_SCHEMES),
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
    aead_algorithm: &ring::aead::AES_256_GCM,
    build_tls12_encrypter: Some(cipher::build_tls12_gcm_256_encrypter),
    build_tls12_decrypter: Some(cipher::build_tls12_gcm_256_decrypter),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: Some(TLS12_ECDSA_SCHEMES),
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::AES_128_GCM,
    build_tls12_encrypter: Some(cipher::build_tls12_gcm_128_encrypter),
    build_tls12_decrypter: Some(cipher::build_tls12_gcm_128_decrypter),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: Some(TLS12_ECDSA_SCHEMES),
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
    aead_algorithm: &ring::aead::AES_256_GCM,
    build_tls12_encrypter: Some(cipher::build_tls12_gcm_256_encrypter),
    build_tls12_decrypter: Some(cipher::build_tls12_gcm_256_decrypter),
};

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: None,
    bulk: BulkAlgorithm::CHACHA20_POLY1305,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 32,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::CHACHA20_POLY1305,
    build_tls12_encrypter: None,
    build_tls12_decrypter: None,
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: None,
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
    aead_algorithm: &ring::aead::AES_256_GCM,
    build_tls12_encrypter: None,
    build_tls12_decrypter: None,
};

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: None,
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::AES_128_GCM,
    build_tls12_encrypter: None,
    build_tls12_decrypter: None,
};

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHERSUITES: [&SupportedCipherSuite; 9] = [
    // TLS1.3 suites
    &TLS13_CHACHA20_POLY1305_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_AES_128_GCM_SHA256,
    // TLS1.2 suites
    &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

// These both O(N^2)!
pub fn choose_ciphersuite_preferring_client(
    client_suites: &[CipherSuite],
    server_suites: &[&'static SupportedCipherSuite],
) -> Option<&'static SupportedCipherSuite> {
    for client_suite in client_suites {
        if let Some(selected) = server_suites
            .iter()
            .find(|x| *client_suite == x.suite)
        {
            return Some(*selected);
        }
    }

    None
}

pub fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[&'static SupportedCipherSuite],
) -> Option<&'static SupportedCipherSuite> {
    if let Some(selected) = server_suites
        .iter()
        .find(|x| client_suites.contains(&x.suite))
    {
        return Some(*selected);
    }

    None
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with `SignatureAlgorithm` `sigalg` removed.
pub fn reduce_given_sigalg(
    all: &[&'static SupportedCipherSuite],
    sigalg: SignatureAlgorithm,
) -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_sigalg(sigalg))
        .cloned()
        .collect()
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with the chosen `version` removed.
pub fn reduce_given_version(
    all: &[&'static SupportedCipherSuite],
    version: ProtocolVersion,
) -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_version(version))
        .cloned()
        .collect()
}

/// Return true if `sigscheme` is usable by any of the given suites.
pub fn compatible_sigscheme_for_suites(
    sigscheme: SignatureScheme,
    common_suites: &[&'static SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.sign();
    common_suites
        .iter()
        .any(|&suite| suite.usable_for_sigalg(sigalg))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::msgs::enums::CipherSuite;

    #[test]
    fn test_client_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        let chosen = choose_ciphersuite_preferring_client(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_server_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        let chosen = choose_ciphersuite_preferring_server(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_pref_fails() {
        assert!(choose_ciphersuite_preferring_client(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            &ALL_CIPHERSUITES
        )
        .is_none());
        assert!(choose_ciphersuite_preferring_server(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            &ALL_CIPHERSUITES
        )
        .is_none());
    }

    #[test]
    fn test_scs_is_debug() {
        println!("{:?}", ALL_CIPHERSUITES);
    }

    #[test]
    fn test_usable_for_version() {
        fn ok_tls13(scs: &SupportedCipherSuite) {
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(scs.usable_for_version(ProtocolVersion::TLSv1_3));
        }

        fn ok_tls12(scs: &SupportedCipherSuite) {
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
            assert!(scs.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_3));
        }

        ok_tls13(&TLS13_CHACHA20_POLY1305_SHA256);
        ok_tls13(&TLS13_AES_256_GCM_SHA384);
        ok_tls13(&TLS13_AES_128_GCM_SHA256);

        ok_tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        ok_tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        ok_tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_can_resume_to() {
        assert!(TLS13_CHACHA20_POLY1305_SHA256.can_resume_to(&TLS13_AES_128_GCM_SHA256));
        assert!(!TLS13_CHACHA20_POLY1305_SHA256.can_resume_to(&TLS13_AES_256_GCM_SHA384));
        assert!(!TLS13_CHACHA20_POLY1305_SHA256
            .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256));
        assert!(!TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256));
        assert!(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256));
    }
}
