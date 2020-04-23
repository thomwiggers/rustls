use crate::cipher;
use crate::client::ClientSessionImpl;
use crate::error::TLSError;
use crate::handshake::{check_handshake_message, check_message};
use crate::hash_hs;
use crate::key_schedule::{KeySchedule, SecretKind};
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, Compression, NamedGroup, ProtocolVersion};
use crate::msgs::enums::{ClientCertificateType, ECPointFormat, PSKKeyExchangeMode};
use crate::msgs::enums::{ContentType, ExtensionType, HandshakeType, SignatureScheme};
use crate::msgs::handshake::DecomposedSignatureScheme;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::ServerKeyExchangePayload;
use crate::msgs::handshake::{CertificateEntry, CertificatePayloadTLS13};
use crate::msgs::handshake::{CertificateStatusRequest, SCTList};
use crate::msgs::handshake::{ClientExtension, HasServerExtensions};
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{ConvertProtocolNameList, ProtocolNameList};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{EncryptedExtensions, KeyShareEntry};
use crate::msgs::handshake::{HelloRetryRequest, PresharedKeyIdentity, PresharedKeyOffer};
use crate::msgs::handshake::{Random, ServerHelloPayload, SessionID};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::rand;
use crate::session::SessionSecrets;
use crate::sign;
use crate::suites;
use crate::ticketer;
use crate::verify;
#[cfg(feature = "quic")]
use crate::{msgs::base::PayloadU16, quic, session::Protocol};

use crate::client::common::{ClientAuthDetails, ClientHelloDetails, ReceivedTicketDetails};
use crate::client::common::{HandshakeDetails, ServerCertDetails, ServerKXDetails};

use crate::client::default_group::DEFAULT_GROUP;

use ring::constant_time;
use std::mem;
use webpki;

macro_rules! extract_handshake(
  ( $m:expr, $t:path ) => (
    match $m.payload {
      MessagePayload::Handshake(ref hsp) => match hsp.payload {
        $t(ref hm) => Some(hm),
        _ => None
      },
      _ => None
    }
  )
);

macro_rules! extract_handshake_mut(
  ( $m:expr, $t:path ) => (
    match $m.payload {
      MessagePayload::Handshake(hsp) => match hsp.payload {
        $t(hm) => Some(hm),
        _ => None
      },
      _ => None
    }
  )
);

type CheckResult = Result<(), TLSError>;
type NextState = Box<dyn State + Send + Sync>;
type NextStateOrError = Result<NextState, TLSError>;

pub trait State {
    fn check_message(&self, m: &Message) -> CheckResult;
    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError;
}

fn illegal_param(sess: &mut ClientSessionImpl, why: &str) -> TLSError {
    sess.common
        .send_fatal_alert(AlertDescription::IllegalParameter);
    TLSError::PeerMisbehavedError(why.to_string())
}

fn check_aligned_handshake(sess: &mut ClientSessionImpl) -> Result<(), TLSError> {
    if !sess.common.handshake_joiner.is_empty() {
        Err(illegal_param(sess, "keys changed with pending hs fragment"))
    } else {
        Ok(())
    }
}

fn find_session(
    sess: &mut ClientSessionImpl,
    dns_name: webpki::DNSNameRef,
) -> Option<persist::ClientSessionValue> {
    let key = persist::ClientSessionKey::session_for_dns_name(dns_name);
    let key_buf = key.get_encoding();

    let maybe_value = sess.config.session_persistence.get(&key_buf);

    if maybe_value.is_none() {
        debug!("No cached session for {:?}", dns_name);
        return None;
    }

    let value = maybe_value.unwrap();
    let mut reader = Reader::init(&value[..]);
    if let Some(result) = persist::ClientSessionValue::read(&mut reader) {
        if result.has_expired(ticketer::timebase()) {
            None
        } else {
            #[cfg(feature = "quic")]
            {
                if sess.common.protocol == Protocol::Quic {
                    let params = PayloadU16::read(&mut reader)?;
                    sess.common.quic.params = Some(params.0);
                }
            }
            Some(result)
        }
    } else {
        None
    }
}

#[allow(unused)]
fn find_kx_hint(sess: &mut ClientSessionImpl, dns_name: webpki::DNSNameRef) -> Option<NamedGroup> {
    let key = persist::ClientSessionKey::hint_for_dns_name(dns_name);
    let key_buf = key.get_encoding();

    let maybe_value = sess.config.session_persistence.get(&key_buf);
    maybe_value.and_then(|enc| NamedGroup::read_bytes(&enc))
}

fn save_kx_hint(sess: &mut ClientSessionImpl, dns_name: webpki::DNSNameRef, group: NamedGroup) {
    let key = persist::ClientSessionKey::hint_for_dns_name(dns_name);

    sess.config
        .session_persistence
        .put(key.get_encoding(), group.get_encoding());
}

/// If we have a ticket, we use the sessionid as a signal that we're
/// doing an abbreviated handshake.  See section 3.4 in RFC5077.
fn randomise_sessionid_for_ticket(csv: &mut persist::ClientSessionValue) {
    if !csv.ticket.0.is_empty() {
        let mut random_id = [0u8; 32];
        rand::fill_random(&mut random_id);
        csv.session_id = SessionID::new(&random_id);
    }
}

/// This implements the horrifying TLS1.3 hack where PSK binders have a
/// data dependency on the message they are contained within.
pub fn fill_in_psk_binder(
    sess: &mut ClientSessionImpl,
    handshake: &mut HandshakeDetails,
    hmp: &mut HandshakeMessagePayload,
) {
    // We need to know the hash function of the suite we're trying to resume into.
    let resuming = handshake.resuming_session.as_ref().unwrap();
    let suite_hash = sess
        .find_cipher_suite(resuming.cipher_suite)
        .unwrap()
        .get_hash();

    // The binder is calculated over the clienthello, but doesn't include itself or its
    // length, or the length of its container.
    let binder_plaintext = hmp.get_encoding_for_binder_signing();
    let handshake_hash = sess
        .common
        .hs_transcript
        .get_hash_given(suite_hash, &binder_plaintext);

    let mut empty_hash_ctx = hash_hs::HandshakeHash::new();
    empty_hash_ctx.start_hash(suite_hash);
    let empty_hash = empty_hash_ctx.get_current_hash();

    // Run a fake key_schedule to simulate what the server will do if it choses
    // to resume.
    let mut key_schedule = KeySchedule::new(suite_hash);
    key_schedule.input_secret(&resuming.master_secret.0);
    let base_key = key_schedule.derive(SecretKind::ResumptionPSKBinderKey, &empty_hash);
    let real_binder = key_schedule.sign_verify_data(&base_key, &handshake_hash);

    if let HandshakePayload::ClientHello(ref mut ch) = hmp.payload {
        ch.set_psk_binder(real_binder);
    };
    sess.common.set_key_schedule(key_schedule);
}

struct InitialState {
    handshake: HandshakeDetails,
}

impl InitialState {
    fn new(host_name: webpki::DNSName, extra_exts: Vec<ClientExtension>) -> InitialState {
        InitialState {
            handshake: HandshakeDetails::new(host_name, extra_exts),
        }
    }

    fn emit_initial_client_hello(self, sess: &mut ClientSessionImpl) -> NextState {
        if sess.config.client_auth_cert_resolver.has_certs() {
            sess.common.hs_transcript.set_client_auth_enabled();
        }
        let hello_details = ClientHelloDetails::new();
        emit_client_hello_for_retry(sess, self.handshake, hello_details, None)
    }
}

pub fn start_handshake(
    sess: &mut ClientSessionImpl,
    host_name: webpki::DNSName,
    extra_exts: Vec<ClientExtension>,
) -> NextState {
    InitialState::new(host_name, extra_exts).emit_initial_client_hello(sess)
}

struct ExpectServerHello {
    handshake: HandshakeDetails,
    hello: ClientHelloDetails,
    server_cert: ServerCertDetails,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
}

struct ExpectServerHelloOrHelloRetryRequest(ExpectServerHello);

fn emit_fake_ccs(hs: &mut HandshakeDetails, sess: &mut ClientSessionImpl) {
    #[cfg(feature = "quic")]
    {
        if let Protocol::Quic = sess.common.protocol {
            return;
        }
    }

    if hs.sent_tls13_fake_ccs {
        return;
    }

    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };
    sess.common.send_msg(m, false);
    hs.sent_tls13_fake_ccs = true;
}

fn compatible_suite(
    sess: &ClientSessionImpl,
    resuming_suite: Option<&suites::SupportedCipherSuite>,
) -> bool {
    match resuming_suite {
        Some(resuming_suite) => {
            if let Some(suite) = sess.common.get_suite() {
                suite.can_resume_to(&resuming_suite)
            } else {
                true
            }
        }
        None => false,
    }
}

fn emit_client_hello_for_retry(
    sess: &mut ClientSessionImpl,
    mut handshake: HandshakeDetails,
    mut hello: ClientHelloDetails,
    retryreq: Option<&HelloRetryRequest>,
) -> NextState {
    assert!(retryreq.is_none(), "No retryrequest allowed for testing pqtls");
    // Do we have a SessionID or ticket cached for this host?
    handshake.resuming_session = find_session(sess, handshake.dns_name.as_ref());
    let (session_id, ticket, resume_version) = if handshake.resuming_session.is_some() {
        let resuming = handshake.resuming_session.as_mut().unwrap();
        if resuming.version == ProtocolVersion::TLSv1_2 {
            randomise_sessionid_for_ticket(resuming);
        }
        debug!("Resuming session");
        (
            resuming.session_id,
            resuming.ticket.0.clone(),
            resuming.version,
        )
    } else {
        debug!("Not resuming any session");
        (SessionID::empty(), Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = sess.config.supports_version(ProtocolVersion::TLSv1_2);
    let support_tls13 = sess.config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    let mut key_shares = vec![];

    if support_tls13 {
        // Choose our groups:
        // - if we've been asked via HelloRetryRequest for a specific
        //   one, do that.
        // - if not, we might have a hint of what the server supports
        // - if not, send just DEFAULT_GROUP
        //
        /*
        let groups = retryreq
            .and_then(|req| req.get_requested_key_share_group())
            //.or_else(|| find_kx_hint(sess, handshake.dns_name.as_ref()))
            .or_else(|| Some(DEFAULT_GROUP)) // XXX DEFAULT KEM
            .map(|grp| vec![grp])
            .unwrap();
        */
        let groups = vec![DEFAULT_GROUP];

        for group in groups {
            // in reply to HelloRetryRequest, we must not alter any existing key
            // shares
            if let Some(already_offered_share) = hello.take_key_share(group) {
                key_shares.push(KeyShareEntry::new(
                    group,
                    already_offered_share.pubkey.as_ref(),
                ));
                hello.offered_key_shares.push(already_offered_share);
                continue;
            }

            if let Some(key_share) = suites::KeyExchange::start_ecdhe(group) {
                key_shares.push(KeyShareEntry::new(group, key_share.pubkey.as_ref()));
                hello.offered_key_shares.push(key_share);
            }
        }
    }

    let mut exts = Vec::new();
    if !supported_versions.is_empty() {
        exts.push(ClientExtension::SupportedVersions(supported_versions));
    }
    if sess.config.enable_sni {
        exts.push(ClientExtension::make_sni(handshake.dns_name.as_ref()));
    }
    exts.push(ClientExtension::ECPointFormats(
        ECPointFormatList::supported(),
    ));
    exts.push(ClientExtension::NamedGroups(
        suites::KeyExchange::supported_groups().to_vec(),
    ));
    exts.push(ClientExtension::SignatureAlgorithms(
        verify::supported_verify_schemes().to_vec(),
    ));
    exts.push(ClientExtension::ExtendedMasterSecretRequest);
    exts.push(ClientExtension::CertificateStatusRequest(
        CertificateStatusRequest::build_ocsp(),
    ));

    if sess.config.ct_logs.is_some() {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    if support_tls13 {
        exts.push(ClientExtension::KeyShare(key_shares));
    }

    if let Some(cookie) = retryreq.and_then(|req| req.get_cookie()) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 && sess.config.enable_tickets {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !sess.config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(
            &sess
                .config
                .alpn_protocols
                .iter()
                .map(|proto| &proto[..])
                .collect::<Vec<_>>(),
        )));
    }

    // Extra extensions must be placed before the PSK extension
    exts.extend(handshake.extra_exts.iter().cloned());

    let fill_in_binder = if support_tls13
        && sess.config.enable_tickets
        && resume_version == ProtocolVersion::TLSv1_3
        && !ticket.is_empty()
    {
        let resuming_suite = handshake
            .resuming_session
            .as_ref()
            .and_then(|resume| sess.find_cipher_suite(resume.cipher_suite));

        if compatible_suite(sess, resuming_suite) {
            // The EarlyData extension MUST be supplied together with the
            // PreSharedKey extension.
            let max_early_data_size = handshake
                .resuming_session
                .as_ref()
                .map_or(0, |resume| resume.max_early_data_size);
            if sess.config.enable_early_data && max_early_data_size > 0 && retryreq.is_none() {
                sess.early_data.enable(max_early_data_size as usize);
                exts.push(ClientExtension::EarlyData);
            }

            // Finally, and only for TLS1.3 with a ticket resumption, include a binder
            // for our ticket.  This must go last.
            //
            // Include an empty binder. It gets filled in below because it depends on
            // the message it's contained in (!!!).
            let (obfuscated_ticket_age, suite) = {
                let resuming = handshake.resuming_session.as_ref().unwrap();
                (
                    resuming.get_obfuscated_ticket_age(ticketer::timebase()),
                    resuming.cipher_suite,
                )
            };

            let binder_len = sess.find_cipher_suite(suite).unwrap().get_hash().output_len;
            let binder = vec![0u8; binder_len];

            let psk_identity = PresharedKeyIdentity::new(ticket, obfuscated_ticket_age);
            let psk_ext = PresharedKeyOffer::new(psk_identity, binder);
            exts.push(ClientExtension::PresharedKey(psk_ext));
            true
        } else {
            false
        }
    } else if sess.config.enable_tickets {
        // If we have a ticket, include it.  Otherwise, request one.
        if ticket.is_empty() {
            exts.push(ClientExtension::SessionTicketRequest);
        } else {
            exts.push(ClientExtension::SessionTicketOffer(Payload::new(ticket)));
        }
        false
    } else {
        false
    };

    // Note what extensions we sent.
    hello.sent_extensions = exts.iter().map(|ext| ext.get_type()).collect();

    let mut chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from_slice(&handshake.randoms.client),
            session_id,
            cipher_suites: sess.get_cipher_suites(),
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    if fill_in_binder {
        fill_in_psk_binder(sess, &mut handshake, &mut chp);
    }

    let ch = Message {
        typ: ContentType::Handshake,
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::Handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        emit_fake_ccs(&mut handshake, sess);
    }

    trace!("Sending ClientHello {:#?}", ch);

    sess.common.hs_transcript.add_message(&ch);
    sess.common.send_msg(ch, false);
    println!("EMITTED CH {} ns", handshake.start_time.elapsed().as_nanos());

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    if sess.early_data.is_enabled() {
        // For middlebox compatility
        emit_fake_ccs(&mut handshake, sess);

        // It is safe to call unwrap() because fill_in_binder is true.
        let resuming_suite = handshake
            .resuming_session
            .as_ref()
            .and_then(|resume| sess.find_cipher_suite(resume.cipher_suite))
            .unwrap();

        let client_hello_hash = sess
            .common
            .hs_transcript
            .get_hash_given(resuming_suite.get_hash(), &[]);
        let client_early_traffic_secret = sess
            .common
            .get_key_schedule()
            .derive(SecretKind::ClientEarlyTrafficSecret, &client_hello_hash);
        // Set early data encryption key
        sess.common.set_message_encrypter(cipher::new_tls13_write(
            resuming_suite,
            &client_early_traffic_secret,
        ));

        sess.config.key_log.log(
            sess.common.protocol.labels().client_early_traffic_secret,
            &handshake.randoms.client,
            &client_early_traffic_secret,
        );

        #[cfg(feature = "quic")]
        {
            sess.common.quic.early_secret = Some(client_early_traffic_secret);
        }

        // Now the client can send encrypted early data
        sess.common.early_traffic = true;
        trace!("Starting early data traffic");
        sess.common.we_now_encrypting();
    }

    let next = ExpectServerHello {
        handshake,
        hello,
        server_cert: ServerCertDetails::new(),
        may_send_cert_status: false,
        must_issue_new_ticket: false,
    };

    if support_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest(next))
    } else {
        Box::new(next)
    }
}

// Extensions we expect in plaintext in the ServerHello.
static ALLOWED_PLAINTEXT_EXTS: &'static [ExtensionType] = &[
    ExtensionType::KeyShare,
    ExtensionType::PreSharedKey,
    ExtensionType::SupportedVersions,
];

// Only the intersection of things we offer, and those disallowed
// in TLS1.3
static DISALLOWED_TLS13_EXTS: &'static [ExtensionType] = &[
    ExtensionType::ECPointFormats,
    ExtensionType::SessionTicket,
    ExtensionType::RenegotiationInfo,
    ExtensionType::ExtendedMasterSecret,
];

fn validate_server_hello_tls13(
    sess: &mut ClientSessionImpl,
    server_hello: &ServerHelloPayload,
) -> Result<(), TLSError> {
    for ext in &server_hello.extensions {
        if !ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type()) {
            sess.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerMisbehavedError(
                "server sent unexpected cleartext ext".to_string(),
            ));
        }
    }

    Ok(())
}

fn process_alpn_protocol(
    sess: &mut ClientSessionImpl,
    proto: Option<&[u8]>,
) -> Result<(), TLSError> {
    sess.alpn_protocol = proto.map(|s| s.to_owned());
    if sess.alpn_protocol.is_some()
        && !sess
            .config
            .alpn_protocols
            .contains(sess.alpn_protocol.as_ref().unwrap())
    {
        return Err(illegal_param(sess, "server sent non-offered ALPN protocol"));
    }
    debug!("ALPN protocol is {:?}", sess.alpn_protocol);
    Ok(())
}

impl ExpectServerHello {
    fn start_handshake_traffic(
        &mut self,
        sess: &mut ClientSessionImpl,
        server_hello: &ServerHelloPayload,
    ) -> Result<(), TLSError> {
        let suite = sess.common.get_suite_assert();

        if let Some(selected_psk) = server_hello.get_psk_index() {
            if let Some(ref resuming) = self.handshake.resuming_session {
                let resume_from_suite = sess.find_cipher_suite(resuming.cipher_suite).unwrap();
                if !resume_from_suite.can_resume_to(suite) {
                    return Err(TLSError::PeerMisbehavedError(
                        "server resuming incompatible suite".to_string(),
                    ));
                }

                if selected_psk != 0 {
                    return Err(TLSError::PeerMisbehavedError(
                        "server selected invalid psk".to_string(),
                    ));
                }

                debug!("Resuming using PSK");
            // The key schedule has been initialized and set in fill_in_psk()
            // Server must be using the resumption suite, otherwise set_suite()
            // in ExpectServerHello::handle() would fail.
            // key_schedule.input_secret(&resuming.master_secret.0);
            } else {
                return Err(TLSError::PeerMisbehavedError(
                    "server selected unoffered psk".to_string(),
                ));
            }
        } else {
            debug!("Not resuming");
            // Discard the early data key schedule.
            sess.early_data.rejected();
            sess.common.early_traffic = false;
            let mut key_schedule = KeySchedule::new(suite.get_hash());
            key_schedule.input_empty();
            sess.common.set_key_schedule(key_schedule);
            self.handshake.resuming_session.take();
        }

        let their_key_share = server_hello.get_key_share().ok_or_else(|| {
            sess.common
                .send_fatal_alert(AlertDescription::MissingExtension);
            TLSError::PeerMisbehavedError("missing key share".to_string())
        })?;

        // XXX: Get the shared secret for the first phase of encrypting traffic.
        let our_key_share = self
            .hello
            .find_key_share(their_key_share.group)
            .ok_or_else(|| illegal_param(sess, "wrong group for key share"))?;
        let shared = our_key_share
            .clone()
            .decapsulate(&their_key_share.payload.0)
            .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;
        trace!("Shared secret = {:?}", shared.premaster_secret);

        save_kx_hint(
            sess,
            self.handshake.dns_name.as_ref(),
            their_key_share.group,
        );
        sess.common
            .get_mut_key_schedule()
            .input_secret(&shared.premaster_secret);

        check_aligned_handshake(sess)?;

        self.handshake.hash_at_client_recvd_server_hello =
            sess.common.hs_transcript.get_current_hash();

        /*
        if !sess.early_data.is_enabled() {
            // Set the client encryption key for handshakes if early data is not used
            let write_key = sess.common.get_key_schedule()
                .derive(SecretKind::ClientHandshakeTrafficSecret,
                    &self.handshake.hash_at_client_recvd_server_hello);
            sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
            sess.config.key_log.log(sess.common.protocol.labels().client_handshake_traffic_secret,
                                 &self.handshake.randoms.client,
                                 &write_key);
            sess.common.get_mut_key_schedule().current_client_traffic_secret = write_key;
        }*/

        let read_key = sess.common.get_key_schedule().derive(
            SecretKind::ServerHandshakeTrafficSecret,
            &self.handshake.hash_at_client_recvd_server_hello,
        );
        sess.common
            .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
        sess.config.key_log.log(
            sess.common
                .protocol
                .labels()
                .server_handshake_traffic_secret,
            &self.handshake.randoms.client,
            &read_key,
        );
        sess.common
            .get_mut_key_schedule()
            .current_server_traffic_secret = read_key;

        /* Now move to our first set of traffic keys. */
        check_aligned_handshake(sess)?;
        let write_key = sess.common.get_key_schedule().derive(
            SecretKind::ClientHandshakeTrafficSecret,
            &self.handshake.hash_at_client_recvd_server_hello,
        );
        sess.config.key_log.log(
            sess.common
                .protocol
                .labels()
                .client_handshake_traffic_secret,
            &self.handshake.randoms.client,
            &write_key,
        );
        trace!("Client write key: {:?}", &write_key);
        sess.common
            .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

        println!("DERIVED EPHEMERAL KEYS: {} ns", self.handshake.start_time.elapsed().as_nanos());

        #[cfg(feature = "quic")]
        {
            let key_schedule = sess.common.key_schedule.as_ref().unwrap();
            let client = if sess.early_data.is_enabled() {
                // Traffic secret wasn't computed and stored above, so do it here.
                sess.common.get_key_schedule().derive(
                    SecretKind::ClientHandshakeTrafficSecret,
                    &self.handshake.hash_at_client_recvd_server_hello,
                )
            } else {
                key_schedule.current_client_traffic_secret.clone()
            };
            sess.common.quic.hs_secrets = Some(quic::Secrets {
                client,
                server: key_schedule.current_server_traffic_secret.clone(),
            });
        }

        Ok(())
    }

    fn into_expect_tls13_encrypted_extensions(self) -> NextState {
        Box::new(ExpectTLS13EncryptedExtensions {
            handshake: self.handshake,
            server_cert: self.server_cert,
            hello: self.hello,
        })
    }

    fn into_expect_tls12_new_ticket_resume(
        self,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> NextState {
        Box::new(ExpectTLS12NewTicket {
            handshake: self.handshake,
            resuming: true,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_tls12_ccs_resume(
        self,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> NextState {
        Box::new(ExpectTLS12CCS {
            handshake: self.handshake,
            ticket: ReceivedTicketDetails::new(),
            resuming: true,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_tls12_certificate(self) -> NextState {
        Box::new(ExpectTLS12Certificate {
            handshake: self.handshake,
            server_cert: self.server_cert,
            may_send_cert_status: self.may_send_cert_status,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectServerHello {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::ServerHello])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let server_hello = extract_handshake!(m, HandshakePayload::ServerHello).unwrap();
        println!("RECEIVED SH: {} ns", self.handshake.start_time.elapsed().as_nanos());
        trace!("We got ServerHello {:#?}", server_hello);

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = sess.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .get_supported_versions()
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        match server_version {
            TLSv1_3 if tls13_supported => {
                sess.common.negotiated_version = Some(TLSv1_3);
            }
            TLSv1_2 if sess.config.supports_version(TLSv1_2) => {
                if sess.early_data.is_enabled() && sess.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(TLSError::PeerMisbehavedError(
                        "server chose v1.2 when offering 0-rtt".to_string(),
                    ));
                }
                sess.common.negotiated_version = Some(TLSv1_2);

                if server_hello.get_supported_versions().is_some() {
                    return Err(illegal_param(
                        sess,
                        "server chose v1.2 using v1.3 extension",
                    ));
                }
            }
            _ => {
                sess.common
                    .send_fatal_alert(AlertDescription::ProtocolVersion);
                return Err(TLSError::PeerIncompatibleError(
                    "server does not support TLS v1.2/v1.3".to_string(),
                ));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(illegal_param(sess, "server chose non-Null compression"));
        }

        if server_hello.has_duplicate_extension() {
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::PeerMisbehavedError(
                "server sent duplicate extensions".to_string(),
            ));
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            sess.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerMisbehavedError(
                "server sent unsolicited extension".to_string(),
            ));
        }

        // Extract ALPN protocol
        if !sess.common.is_tls13() {
            process_alpn_protocol(sess, server_hello.get_alpn_protocol())?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                sess.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                return Err(TLSError::PeerMisbehavedError(
                    "server does not support uncompressed points".to_string(),
                ));
            }
        }

        let scs = sess.find_cipher_suite(server_hello.cipher_suite);

        if scs.is_none() {
            sess.common
                .send_fatal_alert(AlertDescription::HandshakeFailure);
            return Err(TLSError::PeerMisbehavedError(
                "server chose non-offered ciphersuite".to_string(),
            ));
        }

        debug!("Using ciphersuite {:?}", server_hello.cipher_suite);
        if !sess.common.set_suite(scs.unwrap()) {
            return Err(illegal_param(sess, "server varied selected ciphersuite"));
        }

        let version = sess.common.negotiated_version.unwrap();
        if !sess.common.get_suite_assert().usable_for_version(version) {
            return Err(illegal_param(
                sess,
                "server chose unusable ciphersuite for version",
            ));
        }

        // Start our handshake hash, and input the server-hello.
        let starting_hash = sess.common.get_suite_assert().get_hash();
        sess.common.hs_transcript.start_hash(starting_hash);
        sess.common.hs_transcript.add_message(&m);

        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        if sess.common.is_tls13() {
            validate_server_hello_tls13(sess, server_hello)?;
            self.start_handshake_traffic(sess, server_hello)?;
            emit_fake_ccs(&mut self.handshake, sess);
            return Ok(self.into_expect_tls13_encrypted_extensions());
        }
        unreachable!("Don't support TLS 1.2 anymore");

        // TLS1.2 only from here-on

        // Save ServerRandom and SessionID
        server_hello
            .random
            .write_slice(&mut self.handshake.randoms.server);
        self.handshake.session_id = server_hello.session_id;

        // Look for TLS1.3 downgrade signal in server random
        if tls13_supported && self.handshake.randoms.has_tls12_downgrade_marker() {
            return Err(illegal_param(
                sess,
                "downgrade to TLS1.2 when TLS1.3 is supported",
            ));
        }

        // Doing EMS?
        if server_hello.ems_support_acked() {
            self.handshake.using_ems = true;
        }

        // Might the server send a ticket?
        let with_tickets = if server_hello
            .find_extension(ExtensionType::SessionTicket)
            .is_some()
        {
            debug!("Server supports tickets");
            true
        } else {
            false
        };
        self.must_issue_new_ticket = with_tickets;

        // Might the server send a CertificateStatus between Certificate and
        // ServerKeyExchange?
        if server_hello
            .find_extension(ExtensionType::StatusRequest)
            .is_some()
        {
            debug!("Server may staple OCSP response");
            self.may_send_cert_status = true;
        }

        // Save any sent SCTs for verification against the certificate.
        if let Some(sct_list) = server_hello.get_sct_list() {
            debug!("Server sent {:?} SCTs", sct_list.len());

            if sct_list_is_invalid(sct_list) {
                let error_msg = "server sent invalid SCT list".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }
            self.server_cert.scts = Some(sct_list.clone());
        }

        // See if we're successfully resuming.
        let mut abbreviated_handshake = false;
        if let Some(ref resuming) = self.handshake.resuming_session {
            if resuming.session_id == self.handshake.session_id {
                debug!("Server agreed to resume");
                abbreviated_handshake = true;

                // Is the server telling lies about the ciphersuite?
                if resuming.cipher_suite != scs.unwrap().suite {
                    let error_msg = "abbreviated handshake offered, but with varied cs".to_string();
                    return Err(TLSError::PeerMisbehavedError(error_msg));
                }

                // And about EMS support?
                if resuming.extended_ms != self.handshake.using_ems {
                    let error_msg = "server varied ems support over resume".to_string();
                    return Err(TLSError::PeerMisbehavedError(error_msg));
                }

                let secrets = SessionSecrets::new_resume(
                    &self.handshake.randoms,
                    scs.unwrap().get_hash(),
                    &resuming.master_secret.0,
                );
                sess.config.key_log.log(
                    sess.common.protocol.labels().client_random,
                    &secrets.randoms.client,
                    &secrets.master_secret,
                );
                sess.common.start_encryption_tls12(secrets);
            }
        }

        if abbreviated_handshake {
            // Since we're resuming, we verified the certificate and
            // proof of possession in the prior session.
            let certv = verify::ServerCertVerified::assertion();
            let sigv = verify::HandshakeSignatureValid::assertion();

            if self.must_issue_new_ticket {
                Ok(self.into_expect_tls12_new_ticket_resume(certv, sigv))
            } else {
                Ok(self.into_expect_tls12_ccs_resume(certv, sigv))
            }
        } else {
            Ok(self.into_expect_tls12_certificate())
        }
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.0)
    }

    fn handle_hello_retry_request(
        self,
        sess: &mut ClientSessionImpl,
        m: Message,
    ) -> NextStateOrError {
        check_handshake_message(&m, &[HandshakeType::HelloRetryRequest])?;

        let hrr = extract_handshake!(m, HandshakePayload::HelloRetryRequest).unwrap();
        trace!("Got HRR {:?}", hrr);

        let has_cookie = hrr.get_cookie().is_some();
        let req_group = hrr.get_requested_key_share_group();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if !has_cookie
            && req_group
                .map(|g| self.0.hello.has_key_share(g))
                .unwrap_or(false)
        {
            return Err(illegal_param(sess, "server requested hrr with our group"));
        }

        // Or asks for us to retry on an unsupported group.
        if let Some(group) = req_group {
            if !suites::KeyExchange::supported_groups().contains(&group) {
                return Err(illegal_param(sess, "server requested hrr with bad group"));
            }
        }

        // Or has an empty cookie.
        if has_cookie && hrr.get_cookie().unwrap().0.is_empty() {
            return Err(illegal_param(
                sess,
                "server requested hrr with empty cookie",
            ));
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            sess.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerIncompatibleError(
                "server sent hrr with unhandled extension".to_string(),
            ));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(illegal_param(sess, "server send duplicate hrr extensions"));
        }

        // Or asks us to change nothing.
        if !has_cookie && req_group.is_none() {
            return Err(illegal_param(sess, "server requested hrr with no changes"));
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(illegal_param(
                    sess,
                    "server requested unsupported version in hrr",
                ));
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = sess.find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(illegal_param(
                    sess,
                    "server requested unsupported cs in hrr",
                ));
            }
        };

        // HRR selects the ciphersuite.
        sess.common.set_suite(cs);

        // This is the draft19 change where the transcript became a tree
        sess.common.hs_transcript.start_hash(cs.get_hash());
        sess.common.hs_transcript.rollup_for_hrr();
        sess.common.hs_transcript.add_message(&m);

        // Early data is not alllowed after HelloRetryrequest
        if sess.early_data.is_enabled() {
            sess.early_data.rejected();
        }

        Ok(emit_client_hello_for_retry(
            sess,
            self.0.handshake,
            self.0.hello,
            Some(hrr),
        ))
    }
}

impl State for ExpectServerHelloOrHelloRetryRequest {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(
            m,
            &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
        )
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        if m.is_handshake_type(HandshakeType::ServerHello) {
            self.into_expect_server_hello().handle(sess, m)
        } else {
            self.handle_hello_retry_request(sess, m)
        }
    }
}

fn validate_encrypted_extensions(
    sess: &mut ClientSessionImpl,
    hello: &ClientHelloDetails,
    exts: &EncryptedExtensions,
) -> Result<(), TLSError> {
    if exts.has_duplicate_extension() {
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::PeerMisbehavedError(
            "server sent duplicate encrypted extensions".to_string(),
        ));
    }

    if hello.server_sent_unsolicited_extensions(exts, &[]) {
        sess.common
            .send_fatal_alert(AlertDescription::UnsupportedExtension);
        let msg = "server sent unsolicited encrypted extension".to_string();
        return Err(TLSError::PeerMisbehavedError(msg));
    }

    for ext in exts {
        if ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type())
            || DISALLOWED_TLS13_EXTS.contains(&ext.get_type())
        {
            sess.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            let msg = "server sent inappropriate encrypted extension".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }
    }

    Ok(())
}

struct ExpectTLS13EncryptedExtensions {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    hello: ClientHelloDetails,
}

impl ExpectTLS13EncryptedExtensions {
    fn into_expect_tls13_finished_resume(
        self,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> NextState {
        Box::new(ExpectTLS13Finished {
            handshake: self.handshake,
            client_auth: None,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_tls13_certificate_or_certreq(self) -> NextState {
        Box::new(ExpectTLS13CertificateOrCertReq {
            handshake: self.handshake,
            server_cert: self.server_cert,
        })
    }
}

impl State for ExpectTLS13EncryptedExtensions {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::EncryptedExtensions])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let exts = extract_handshake!(m, HandshakePayload::EncryptedExtensions).unwrap();
        debug!("TLS1.3 encrypted extensions: {:?}", exts);
        sess.common.hs_transcript.add_message(&m);

        validate_encrypted_extensions(sess, &self.hello, exts)?;
        process_alpn_protocol(sess, exts.get_alpn_protocol())?;

        #[cfg(feature = "quic")]
        {
            // QUIC transport parameters
            if let Some(params) = exts.get_quic_params_extension() {
                sess.common.quic.params = Some(params);
            }
        }

        if self.handshake.resuming_session.is_some() {
            let was_early_traffic = sess.common.early_traffic;
            if was_early_traffic {
                if exts.early_data_extension_offered() {
                    sess.early_data.accepted();
                } else {
                    sess.early_data.rejected();
                    sess.common.early_traffic = false;
                }
            }

            if was_early_traffic && !sess.common.early_traffic {
                // If no early traffic, set the encryption key for handshakes
                let suite = sess.common.get_suite_assert();
                let write_key = sess.common.get_key_schedule().derive(
                    SecretKind::ClientHandshakeTrafficSecret,
                    &self.handshake.hash_at_client_recvd_server_hello,
                );
                sess.common
                    .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
                sess.config.key_log.log(
                    sess.common
                        .protocol
                        .labels()
                        .client_handshake_traffic_secret,
                    &self.handshake.randoms.client,
                    &write_key,
                );
                sess.common
                    .get_mut_key_schedule()
                    .current_client_traffic_secret = write_key;
            }
            let certv = verify::ServerCertVerified::assertion();
            let sigv = verify::HandshakeSignatureValid::assertion();
            Ok(self.into_expect_tls13_finished_resume(certv, sigv))
        } else {
            if exts.early_data_extension_offered() {
                let msg = "server sent early data extension without resumption".to_string();
                return Err(TLSError::PeerMisbehavedError(msg));
            }
            Ok(self.into_expect_tls13_certificate_or_certreq())
        }
    }
}

fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

struct ExpectTLS13Certificate {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
}

impl ExpectTLS13Certificate {
    fn into_expect_tls13_finished(self, certv: verify::ServerCertVerified) -> NextState {
        Box::new(ExpectTLS13Finished {
            handshake: self.handshake,
            client_auth: self.client_auth,
            cert_verified: certv,
            sig_verified: verify::HandshakeSignatureValid::assertion(),
        })
    }

    fn emit_clientkx(&self, session: &mut ClientSessionImpl) {
        let cert = &self.server_cert.cert_chain[0];
        let cert_in = untrusted::Input::from(&cert.0);
        let cert = webpki::EndEntityCert::from(cert_in)
            .map_err(TLSError::WebPKIError)
            .unwrap();
        debug_assert!(cert.is_kem_cert());

        println!("ENCAPSULATING TO SERVER: {} ns", self.handshake.start_time.elapsed().as_nanos());
        let (algorithm, _) = cert.public_key().expect("couldn't get PK");
        debug!("Cert algorithm: {}", algorithm);
        let (ciphertext, shared_secret) = cert.encapsulate().unwrap();

        let ckx = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientKeyExchange,
                payload: HandshakePayload::ClientKeyExchange(Payload::new(
                    ciphertext.as_ref().to_vec(),
                )),
            }),
        };

        session.common.hs_transcript.add_message(&ckx);
        session.common.send_msg(ckx, true);
        println!("SUBMITTED CKEX TO SERVER: {} ns", self.handshake.start_time.elapsed().as_nanos());

        session
            .common
            .get_mut_key_schedule()
            .input_secret(&shared_secret);
        let handshake_hash = &session.common.hs_transcript.get_current_hash();
        session
            .common
            .get_mut_key_schedule()
            .derive_with_hash(handshake_hash);
        check_aligned_handshake(session).unwrap();

        let suite = session.common.get_suite_assert();
        let sess = session;
        // Set the client encryption key for handshakes if early data is not used
        let write_key = sess.common.get_key_schedule().derive(
            SecretKind::ClientAuthenticatedHandshakeTrafficSecret,
            handshake_hash,
        );
        sess.common
            .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
        sess.config.key_log.log(
            sess.common
                .protocol
                .labels()
                .client_handshake_traffic_secret,
            &self.handshake.randoms.client,
            &write_key,
        );
        sess.common
            .get_mut_key_schedule()
            .current_client_traffic_secret = write_key;

        let read_key = sess.common.get_key_schedule().derive(
            SecretKind::ServerAuthenticatedHandshakeTrafficSecret,
            &handshake_hash,
        );
        sess.common
            .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
        sess.config.key_log.log(
            sess.common
                .protocol
                .labels()
                .server_handshake_traffic_secret,
            &self.handshake.randoms.client,
            &read_key,
        );
        sess.common
            .get_mut_key_schedule()
            .current_server_traffic_secret = read_key;
        println!("SWITCHED TO AHS KEYS: {} ns", self.handshake.start_time.elapsed().as_nanos());
    }
}

impl State for ExpectTLS13Certificate {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Certificate])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let cert_chain = extract_handshake!(m, HandshakePayload::CertificateTLS13).unwrap();
        sess.common.hs_transcript.add_message(&m);

        // This is only non-empty for client auth.
        if !cert_chain.context.0.is_empty() {
            warn!("certificate with non-empty context during handshake");
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
        }

        if cert_chain.any_entry_has_duplicate_extension()
            || cert_chain.any_entry_has_unknown_extension()
        {
            warn!("certificate chain contains unsolicited/unknown extension");
            sess.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerMisbehavedError(
                "bad cert chain extensions".to_string(),
            ));
        }

        self.server_cert.ocsp_response = cert_chain.get_end_entity_ocsp();
        self.server_cert.scts = cert_chain.get_end_entity_scts();
        self.server_cert.cert_chain = cert_chain.convert();

        if let Some(sct_list) = self.server_cert.scts.as_ref() {
            if sct_list_is_invalid(sct_list) {
                let error_msg = "server sent invalid SCT list".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }

            if sess.config.ct_logs.is_none() {
                let error_msg = "server sent unsolicited SCT list".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }
        }

        let certv = sess
            .config
            .get_verifier()
            .verify_server_cert(
                &sess.config.root_store,
                &self.server_cert.cert_chain,
                self.handshake.dns_name.as_ref(),
                &self.server_cert.ocsp_response,
            )
            .map_err(|err| send_cert_error_alert(sess, err))?;

        self.emit_clientkx(sess);
        emit_finished_tls13(&self.handshake, sess);

        Ok(self.into_expect_tls13_finished(certv))
    }
}

struct ExpectTLS12Certificate {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
}

impl ExpectTLS12Certificate {
    fn into_expect_tls12_certificate_status_or_server_kx(self) -> NextState {
        Box::new(ExpectTLS12CertificateStatusOrServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }

    fn into_expect_tls12_server_kx(self) -> NextState {
        Box::new(ExpectTLS12ServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectTLS12Certificate {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Certificate])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
        sess.common.hs_transcript.add_message(&m);

        self.server_cert.cert_chain = cert_chain.clone();

        if self.may_send_cert_status {
            Ok(self.into_expect_tls12_certificate_status_or_server_kx())
        } else {
            Ok(self.into_expect_tls12_server_kx())
        }
    }
}

struct ExpectTLS12CertificateStatus {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl ExpectTLS12CertificateStatus {
    fn into_expect_tls12_server_kx(self) -> NextState {
        Box::new(ExpectTLS12ServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectTLS12CertificateStatus {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateStatus])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        sess.common.hs_transcript.add_message(&m);
        let mut status = extract_handshake_mut!(m, HandshakePayload::CertificateStatus).unwrap();

        self.server_cert.ocsp_response = status.take_ocsp_response();
        debug!(
            "Server stapled OCSP response is {:?}",
            self.server_cert.ocsp_response
        );
        Ok(self.into_expect_tls12_server_kx())
    }
}

struct ExpectTLS12CertificateStatusOrServerKX {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl ExpectTLS12CertificateStatusOrServerKX {
    fn into_expect_tls12_server_kx(self) -> NextState {
        Box::new(ExpectTLS12ServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }

    fn into_expect_tls12_certificate_status(self) -> NextState {
        Box::new(ExpectTLS12CertificateStatus {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectTLS12CertificateStatusOrServerKX {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(
            m,
            &[
                HandshakeType::ServerKeyExchange,
                HandshakeType::CertificateStatus,
            ],
        )
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        if m.is_handshake_type(HandshakeType::ServerKeyExchange) {
            self.into_expect_tls12_server_kx().handle(sess, m)
        } else {
            self.into_expect_tls12_certificate_status().handle(sess, m)
        }
    }
}

struct ExpectTLS13CertificateOrCertReq {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
}

impl ExpectTLS13CertificateOrCertReq {
    fn into_expect_tls13_certificate(self) -> NextState {
        Box::new(ExpectTLS13Certificate {
            handshake: self.handshake,
            server_cert: self.server_cert,
            client_auth: None,
        })
    }

    fn into_expect_tls13_certificate_req(self) -> NextState {
        Box::new(ExpectTLS13CertificateRequest {
            handshake: self.handshake,
            server_cert: self.server_cert,
        })
    }
}

impl State for ExpectTLS13CertificateOrCertReq {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(
            m,
            &[
                HandshakeType::Certificate,
                HandshakeType::CertificateRequest,
            ],
        )
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        if m.is_handshake_type(HandshakeType::Certificate) {
            self.into_expect_tls13_certificate().handle(sess, m)
        } else {
            self.into_expect_tls13_certificate_req().handle(sess, m)
        }
    }
}

struct ExpectTLS12ServerKX {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl ExpectTLS12ServerKX {
    fn into_expect_tls12_server_done_or_certreq(self, skx: ServerKXDetails) -> NextState {
        Box::new(ExpectTLS12ServerDoneOrCertReq {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: skx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectTLS12ServerKX {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::ServerKeyExchange])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let opaque_kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();
        let maybe_decoded_kx = opaque_kx.unwrap_given_kxa(&sess.common.get_suite_assert().kx);
        sess.common.hs_transcript.add_message(&m);

        if maybe_decoded_kx.is_none() {
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
        }

        let decoded_kx = maybe_decoded_kx.unwrap();

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        decoded_kx.encode_params(&mut kx_params);
        let skx = ServerKXDetails::new(kx_params, decoded_kx.get_sig().unwrap());

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        {
            if let ServerKeyExchangePayload::ECDHE(ecdhe) = decoded_kx {
                debug!("ECDHE curve is {:?}", ecdhe.params.curve_params);
            }
        }

        Ok(self.into_expect_tls12_server_done_or_certreq(skx))
    }
}

// --- TLS1.3 CertificateVerify ---
struct ExpectTLS13CertificateVerify {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
    hello: ClientHelloDetails,
}

impl ExpectTLS13CertificateVerify {
    fn into_expect_tls13_finished(
        self,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> NextState {
        Box::new(ExpectTLS13Finished {
            handshake: self.handshake,
            client_auth: self.client_auth,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }
}

fn send_cert_error_alert(sess: &mut ClientSessionImpl, err: TLSError) -> TLSError {
    match err {
        TLSError::WebPKIError(webpki::Error::BadDER) => {
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
        }
        TLSError::PeerMisbehavedError(_) => {
            sess.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            sess.common
                .send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}

impl State for ExpectTLS13CertificateVerify {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateVerify])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        // no longer used.
        let cert_verify = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();

        debug!("Server cert is {:?}", self.server_cert.cert_chain);

        // 1. Verify the certificate chain.
        if self.server_cert.cert_chain.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        let certv = sess
            .config
            .get_verifier()
            .verify_server_cert(
                &sess.config.root_store,
                &self.server_cert.cert_chain,
                self.handshake.dns_name.as_ref(),
                &self.server_cert.ocsp_response,
            )
            .map_err(|err| send_cert_error_alert(sess, err))?;

        // 2. Verify their signature on the handshake.
        let handshake_hash = sess.common.hs_transcript.get_current_hash();
        // XXX Add our secret key to the verification to compute MAC key
        let cert = &self.server_cert.cert_chain[0];
        // XXX find key share from certificate type.
        let our_key_share = self
            .hello
            .find_key_share(NamedGroup::KYBER512)
            .ok_or_else(|| illegal_param(sess, "wrong group for key share"))?;
        let sigv = verify::verify_tls13(
            cert,
            our_key_share,
            cert_verify,
            &handshake_hash,
            b"TLS 1.3, server CertificateVerify\x00",
        )
        .map_err(|err| send_cert_error_alert(sess, err))?;

        // 3. Verify any included SCTs.
        match (self.server_cert.scts.as_ref(), sess.config.ct_logs) {
            (Some(scts), Some(logs)) => {
                verify::verify_scts(&self.server_cert.cert_chain[0], scts, logs)?;
            }
            (_, _) => {}
        }

        sess.server_cert_chain = self.server_cert.take_chain();
        sess.common.hs_transcript.add_message(&m);

        Ok(self.into_expect_tls13_finished(certv, sigv))
    }
}

fn emit_certificate(client_auth: &mut ClientAuthDetails, sess: &mut ClientSessionImpl) {
    let chosen_cert = client_auth.cert.take();

    let cert = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(chosen_cert.unwrap_or_else(Vec::new)),
        }),
    };

    sess.common.hs_transcript.add_message(&cert);
    sess.common.send_msg(cert, false);
}

fn emit_clientkx(sess: &mut ClientSessionImpl, kxd: &suites::KeyExchangeResult) {
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(Vec::from(kxd.ciphertext.as_ref().unwrap().as_ref()));
    ecpoint.encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(pubkey),
        }),
    };

    sess.common.hs_transcript.add_message(&ckx);
    sess.common.send_msg(ckx, false);
}

fn emit_certverify(
    client_auth: &mut ClientAuthDetails,
    sess: &mut ClientSessionImpl,
) -> Result<(), TLSError> {
    if client_auth.signer.is_none() {
        trace!("Not sending CertificateVerify, no key");
        sess.common.hs_transcript.abandon_client_auth();
        return Ok(());
    }

    let message = sess.common.hs_transcript.take_handshake_buf();
    let signer = client_auth.signer.take().unwrap();
    let scheme = signer.get_scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(body),
        }),
    };

    sess.common.hs_transcript.add_message(&m);
    sess.common.send_msg(m, false);
    Ok(())
}

fn emit_ccs(sess: &mut ClientSessionImpl) {
    let ccs = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    sess.common.send_msg(ccs, false);
    sess.common.we_now_encrypting();
}

fn emit_finished(sess: &mut ClientSessionImpl) {
    let vh = sess.common.hs_transcript.get_current_hash();
    let verify_data = sess
        .common
        .secrets
        .as_ref()
        .unwrap()
        .client_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    sess.common.hs_transcript.add_message(&f);
    sess.common.send_msg(f, true);
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
struct ExpectTLS12CertificateRequest {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    must_issue_new_ticket: bool,
}

impl ExpectTLS12CertificateRequest {
    fn into_expect_tls12_server_done(self, client_auth: ClientAuthDetails) -> NextState {
        Box::new(ExpectTLS12ServerDone {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectTLS12CertificateRequest {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateRequest])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let certreq = extract_handshake!(m, HandshakePayload::CertificateRequest).unwrap();
        sess.common.hs_transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        let mut client_auth = ClientAuthDetails::new();

        // The RFC jovially describes the design here as 'somewhat complicated'
        // and 'somewhat underspecified'.  So thanks for that.

        // We only support RSA signing at the moment.  If you don't support that,
        // we're not doing client auth.
        if !certreq.certtypes.contains(&ClientCertificateType::RSASign) {
            warn!("Server asked for client auth but without RSASign");
            return Ok(self.into_expect_tls12_server_done(client_auth));
        }

        let canames = certreq
            .canames
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey = sess
            .config
            .client_auth_cert_resolver
            .resolve(&canames, &certreq.sigschemes);

        if let Some(mut certkey) = maybe_certkey {
            debug!("Attempting client auth");
            let maybe_signer = certkey.key.choose_scheme(&certreq.sigschemes);
            client_auth.cert = Some(certkey.take_cert());
            client_auth.signer = maybe_signer;
        } else {
            debug!("Client auth requested but no cert/sigscheme available");
        }

        Ok(self.into_expect_tls12_server_done(client_auth))
    }
}

// TLS1.3 version of the above.  We then move to expecting the server Certificate.
// Unfortunately the CertificateRequest type changed in an annoying way in TLS1.3.
struct ExpectTLS13CertificateRequest {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
}

impl ExpectTLS13CertificateRequest {
    fn into_expect_tls13_certificate(self, client_auth: ClientAuthDetails) -> NextState {
        Box::new(ExpectTLS13Certificate {
            handshake: self.handshake,
            server_cert: self.server_cert,
            client_auth: Some(client_auth),
        })
    }
}

impl State for ExpectTLS13CertificateRequest {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateRequest])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let certreq = &extract_handshake!(m, HandshakePayload::CertificateRequestTLS13).unwrap();
        sess.common.hs_transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        // Fortunately the problems here in TLS1.2 and prior are corrected in
        // TLS1.3.

        // Must be empty during handshake.
        if !certreq.context.0.is_empty() {
            warn!("Server sent non-empty certreq context");
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
        }

        let tls13_sign_schemes = sign::supported_sign_tls13();
        let no_sigschemes = Vec::new();
        let compat_sigschemes = certreq
            .get_sigalgs_extension()
            .unwrap_or(&no_sigschemes)
            .iter()
            .cloned()
            .filter(|scheme| tls13_sign_schemes.contains(scheme))
            .collect::<Vec<SignatureScheme>>();

        if compat_sigschemes.is_empty() {
            sess.common
                .send_fatal_alert(AlertDescription::HandshakeFailure);
            return Err(TLSError::PeerIncompatibleError(
                "server sent bad certreq schemes".to_string(),
            ));
        }

        let no_canames = Vec::new();
        let canames = certreq
            .get_authorities_extension()
            .unwrap_or(&no_canames)
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey = sess
            .config
            .client_auth_cert_resolver
            .resolve(&canames, &compat_sigschemes);

        let mut client_auth = ClientAuthDetails::new();
        if let Some(mut certkey) = maybe_certkey {
            debug!("Attempting client auth");
            let maybe_signer = certkey.key.choose_scheme(&compat_sigschemes);
            client_auth.cert = Some(certkey.take_cert());
            client_auth.signer = maybe_signer;
            client_auth.auth_context = Some(certreq.context.0.clone());
        } else {
            debug!("Client auth requested but no cert selected");
        }

        Ok(self.into_expect_tls13_certificate(client_auth))
    }
}

struct ExpectTLS12ServerDoneOrCertReq {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    must_issue_new_ticket: bool,
}

impl ExpectTLS12ServerDoneOrCertReq {
    fn into_expect_tls12_certificate_req(self) -> NextState {
        Box::new(ExpectTLS12CertificateRequest {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }

    fn into_expect_tls12_server_done(self) -> NextState {
        Box::new(ExpectTLS12ServerDone {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: None,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl State for ExpectTLS12ServerDoneOrCertReq {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(
            m,
            &[
                HandshakeType::CertificateRequest,
                HandshakeType::ServerHelloDone,
            ],
        )
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        if extract_handshake!(m, HandshakePayload::CertificateRequest).is_some() {
            self.into_expect_tls12_certificate_req().handle(sess, m)
        } else {
            sess.common.hs_transcript.abandon_client_auth();
            self.into_expect_tls12_server_done().handle(sess, m)
        }
    }
}

struct ExpectTLS12ServerDone {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
}

impl ExpectTLS12ServerDone {
    fn into_expect_tls12_new_ticket(
        self,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> NextState {
        Box::new(ExpectTLS12NewTicket {
            handshake: self.handshake,
            resuming: false,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_tls12_ccs(
        self,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> NextState {
        Box::new(ExpectTLS12CCS {
            handshake: self.handshake,
            ticket: ReceivedTicketDetails::new(),
            resuming: false,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }
}

impl State for ExpectTLS12ServerDone {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::ServerHelloDone])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let mut st = *self;
        sess.common.hs_transcript.add_message(&m);

        debug!("Server cert is {:?}", st.server_cert.cert_chain);
        debug!("Server DNS name is {:?}", st.handshake.dns_name);

        // 1. Verify the cert chain.
        // 2. Verify any SCTs provided with the certificate.
        // 3. Verify that the top certificate signed their kx.
        // 4. If doing client auth, send our Certificate.
        // 5. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) emit a CCS
        //    e) derive the shared keys, and start encryption
        // 6. emit a Finished, our first encrypted message under the new keys.

        // 1.
        if st.server_cert.cert_chain.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        // XXX Handle kem stuff?
        let certv = sess
            .config
            .get_verifier()
            .verify_server_cert(
                &sess.config.root_store,
                &st.server_cert.cert_chain,
                st.handshake.dns_name.as_ref(),
                &st.server_cert.ocsp_response,
            )
            .map_err(|err| send_cert_error_alert(sess, err))?;

        // 2. Verify any included SCTs.
        match (st.server_cert.scts.as_ref(), sess.config.ct_logs) {
            (Some(scts), Some(logs)) => {
                verify::verify_scts(&st.server_cert.cert_chain[0], scts, logs)?;
            }
            (_, _) => {}
        }

        // This certificate validation doesn't work anymore for KEM certs as they
        // can't sign shit.

        // 3.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sigv = {
            let mut message = Vec::new();
            message.extend_from_slice(&st.handshake.randoms.client);
            message.extend_from_slice(&st.handshake.randoms.server);
            message.extend_from_slice(&st.server_kx.kx_params);

            // Check the signature is compatible with the ciphersuite.
            let sig = &st.server_kx.kx_sig;
            let scs = sess.common.get_suite_assert();
            if scs.sign != sig.scheme.sign() {
                let error_message = format!(
                    "peer signed kx with wrong algorithm (got {:?} expect {:?})",
                    sig.scheme.sign(),
                    scs.sign
                );
                return Err(TLSError::PeerMisbehavedError(error_message));
            }

            verify::verify_signed_struct(&message, &st.server_cert.cert_chain[0], sig)
                .map_err(|err| send_cert_error_alert(sess, err))?
        };
        sess.server_cert_chain = st.server_cert.take_chain();

        // 4.
        if st.client_auth.is_some() {
            emit_certificate(st.client_auth.as_mut().unwrap(), sess);
        }

        // 5a.
        let kxd = sess
            .common
            .get_suite_assert()
            .do_client_kx(&st.server_kx.kx_params)
            .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;

        // 5b.
        emit_clientkx(sess, &kxd);
        // nb. EMS handshake hash only runs up to ClientKeyExchange.
        let handshake_hash = sess.common.hs_transcript.get_current_hash();

        // 5c.
        if st.client_auth.is_some() {
            emit_certverify(st.client_auth.as_mut().unwrap(), sess)?;
        }

        // 5d.
        emit_ccs(sess);

        // 5e. Now commit secrets.
        let hashalg = sess.common.get_suite_assert().get_hash();
        let secrets = if st.handshake.using_ems {
            SessionSecrets::new_ems(
                &st.handshake.randoms,
                &handshake_hash,
                hashalg,
                &kxd.premaster_secret,
            )
        } else {
            SessionSecrets::new(&st.handshake.randoms, hashalg, &kxd.premaster_secret)
        };
        sess.config.key_log.log(
            sess.common.protocol.labels().client_random,
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        sess.common.start_encryption_tls12(secrets);

        // 6.
        emit_finished(sess);

        if st.must_issue_new_ticket {
            Ok(st.into_expect_tls12_new_ticket(certv, sigv))
        } else {
            Ok(st.into_expect_tls12_ccs(certv, sigv))
        }
    }
}

// -- Waiting for their CCS --
struct ExpectTLS12CCS {
    handshake: HandshakeDetails,
    ticket: ReceivedTicketDetails,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectTLS12CCS {
    fn into_expect_tls12_finished(self) -> NextState {
        Box::new(ExpectTLS12Finished {
            handshake: self.handshake,
            ticket: self.ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })
    }
}

impl State for ExpectTLS12CCS {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m, &[ContentType::ChangeCipherSpec], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, _m: Message) -> NextStateOrError {
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        if !sess.common.handshake_joiner.is_empty() {
            warn!("CCS received interleaved with fragmented handshake");
            return Err(TLSError::InappropriateMessage {
                expect_types: vec![ContentType::Handshake],
                got_type: ContentType::ChangeCipherSpec,
            });
        }

        // nb. msgs layer validates trivial contents of CCS
        sess.common.peer_now_encrypting();

        Ok(self.into_expect_tls12_finished())
    }
}

struct ExpectTLS12NewTicket {
    handshake: HandshakeDetails,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectTLS12NewTicket {
    fn into_expect_tls12_ccs(self, ticket: ReceivedTicketDetails) -> NextState {
        Box::new(ExpectTLS12CCS {
            handshake: self.handshake,
            ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })
    }
}

impl State for ExpectTLS12NewTicket {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::NewSessionTicket])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        sess.common.hs_transcript.add_message(&m);

        let nst = extract_handshake_mut!(m, HandshakePayload::NewSessionTicket).unwrap();
        let recvd = ReceivedTicketDetails::from(nst.ticket.0, nst.lifetime_hint);
        Ok(self.into_expect_tls12_ccs(recvd))
    }
}

// -- Waiting for their finished --
fn save_session(
    handshake: &mut HandshakeDetails,
    recvd_ticket: &mut ReceivedTicketDetails,
    sess: &mut ClientSessionImpl,
) {
    // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
    // original ticket again.
    let mut ticket = mem::replace(&mut recvd_ticket.new_ticket, Vec::new());
    if ticket.is_empty() && handshake.resuming_session.is_some() {
        ticket = handshake.resuming_session.as_mut().unwrap().take_ticket();
    }

    if handshake.session_id.is_empty() && ticket.is_empty() {
        debug!("Session not saved: server didn't allocate id or ticket");
        return;
    }

    let key = persist::ClientSessionKey::session_for_dns_name(handshake.dns_name.as_ref());

    let scs = sess.common.get_suite_assert();
    let master_secret = sess.common.secrets.as_ref().unwrap().get_master_secret();
    let version = sess.get_protocol_version().unwrap();
    let mut value = persist::ClientSessionValue::new(
        version,
        scs.suite,
        &handshake.session_id,
        ticket,
        master_secret,
    );
    value.set_times(ticketer::timebase(), recvd_ticket.new_ticket_lifetime, 0);
    if handshake.using_ems {
        value.set_extended_ms_used();
    }

    let worked = sess
        .config
        .session_persistence
        .put(key.get_encoding(), value.get_encoding());

    if worked {
        debug!("Session saved");
    } else {
        debug!("Session not saved");
    }
}

#[allow(unused)]
fn emit_certificate_tls13(client_auth: &mut ClientAuthDetails, sess: &mut ClientSessionImpl) {
    let context = client_auth.auth_context.take().unwrap_or_else(Vec::new);

    let mut cert_payload = CertificatePayloadTLS13 {
        context: PayloadU8::new(context),
        list: Vec::new(),
    };

    if let Some(cert_chain) = client_auth.cert.take() {
        for cert in cert_chain {
            cert_payload.list.push(CertificateEntry::new(cert));
        }
    }

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(cert_payload),
        }),
    };
    sess.common.hs_transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

#[allow(unused)]
fn emit_certverify_tls13(
    client_auth: &mut ClientAuthDetails,
    sess: &mut ClientSessionImpl,
) -> Result<(), TLSError> {
    if client_auth.signer.is_none() {
        debug!("Skipping certverify message (no client scheme/key)");
        return Ok(());
    }

    let mut message = Vec::new();
    message.resize(64, 0x20u8);
    message.extend_from_slice(b"TLS 1.3, client CertificateVerify\x00");
    message.extend_from_slice(&sess.common.hs_transcript.get_current_hash());

    let signer = client_auth.signer.take().unwrap();
    let scheme = signer.get_scheme();
    let sig = signer.sign(&message)?;
    let dss = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(dss),
        }),
    };

    sess.common.hs_transcript.add_message(&m);
    sess.common.send_msg(m, true);
    Ok(())
}

fn emit_finished_tls13(handshake: &HandshakeDetails, sess: &mut ClientSessionImpl) {
    let handshake_hash = sess.common.hs_transcript.get_current_hash();
    debug!(
        "Current client traffic secret: {:?}",
        sess.common.get_key_schedule().current_client_traffic_secret
    );
    let verify_data = sess.common.get_key_schedule().sign_finish(
        SecretKind::ClientAuthenticatedHandshakeTrafficSecret,
        &handshake_hash,
    );
    trace!("handshake_hash: {:?}", &handshake_hash);
    trace!("Verify data: {:?}", &verify_data);
    let verify_data_payload = Payload::new(verify_data);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    sess.common.hs_transcript.add_message(&m);
    sess.common.send_msg(m, true);

    assert!(check_aligned_handshake(sess).is_ok());
    let handshake_hash = sess.common.hs_transcript.get_current_hash();
    let write_key = sess
        .common
        .get_key_schedule()
        .derive(SecretKind::ClientApplicationTrafficSecret, &handshake_hash);
    sess.config.key_log.log(
        sess.common.protocol.labels().client_traffic_secret_0,
        &handshake.randoms.client,
        &write_key,
    );
    let suite = sess.common.get_suite_assert();
    sess.common
        .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
    trace!(
        "Client traffic secret on starting to write: {:?}",
        &write_key
    );
    sess.common
        .get_mut_key_schedule()
        .current_client_traffic_secret = write_key;

    // We need the client to start encrypting here.
    println!("CLIENT ENCRYPTING TRAFFIC: {} ns", 0);
    sess.common.we_now_encrypting();
    sess.common.start_traffic();
}

#[allow(unused)]
fn emit_end_of_early_data_tls13(sess: &mut ClientSessionImpl) {
    #[cfg(feature = "quic")]
    {
        if let Protocol::Quic = sess.common.protocol {
            return;
        }
    }

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EndOfEarlyData,
            payload: HandshakePayload::EndOfEarlyData,
        }),
    };

    sess.common.hs_transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

struct ExpectTLS13Finished {
    handshake: HandshakeDetails,
    #[allow(unused)]
    client_auth: Option<ClientAuthDetails>,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectTLS13Finished {
    fn into_expect_tls13_traffic(self, fin: verify::FinishedMessageVerified) -> ExpectTLS13Traffic {
        ExpectTLS13Traffic {
            handshake: self.handshake,
            _cert_verified: self.cert_verified,
            _sig_verified: self.sig_verified,
            _fin_verified: fin,
        }
    }
}

impl State for ExpectTLS13Finished {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::Finished])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        trace!("Received server finished");
        let st = *self;
        let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

        let handshake_hash = sess.common.hs_transcript.get_current_hash();
        let expect_verify_data = sess.common.get_key_schedule().sign_finish(
            SecretKind::ServerAuthenticatedHandshakeTrafficSecret,
            &handshake_hash,
        );

        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                sess.common.send_fatal_alert(AlertDescription::DecryptError);
                TLSError::DecryptError
            })
            .map(|_| verify::FinishedMessageVerified::assertion())?;
        println!("AUTHENTICATED SERVER: {} ns", st.handshake.start_time.elapsed().as_nanos());

        // Hash this message too.
        sess.common.hs_transcript.add_message(&m);

        let suite = sess.common.get_suite_assert();
        // let maybe_write_key = if sess.common.early_traffic {
        //     /* Derive the client-to-server encryption key before key schedule update */
        //     let key = sess.common
        //         .get_key_schedule()
        //         .derive(SecretKind::ClientHandshakeTrafficSecret,
        //                 &st.handshake.hash_at_client_recvd_server_hello);
        //     Some(key)
        // } else {
        //     None
        // };

        /* Transition to application data */
        sess.common.get_mut_key_schedule().input_empty();

        /* Traffic from server is now decrypted with application data keys. */
        let handshake_hash = sess.common.hs_transcript.get_current_hash();
        let read_key = sess
            .common
            .get_key_schedule()
            .derive(SecretKind::ServerApplicationTrafficSecret, &handshake_hash);
        sess.config.key_log.log(
            sess.common.protocol.labels().server_traffic_secret_0,
            &st.handshake.randoms.client,
            &read_key,
        );
        sess.common
            .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
        sess.common
            .get_mut_key_schedule()
            .current_server_traffic_secret = read_key;

        let exporter_secret = sess
            .common
            .get_key_schedule()
            .derive(SecretKind::ExporterMasterSecret, &handshake_hash);
        sess.config.key_log.log(
            sess.common.protocol.labels().exporter_secret,
            &st.handshake.randoms.client,
            &exporter_secret,
        );
        sess.common.get_mut_key_schedule().current_exporter_secret = exporter_secret;

        // /* The EndOfEarlyData message to server is still encrypted with early data keys,
        //  * but appears in the transcript after the server Finished. */
        // if let Some(write_key) = maybe_write_key {
        //     emit_end_of_early_data_tls13(sess);
        //     sess.common.early_traffic = false;
        //     sess.early_data.finished();
        //     sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
        //     sess.config.key_log.log(sess.common.protocol.labels().client_handshake_traffic_secret,
        //                         &st.handshake.randoms.client,
        //                         &write_key);
        //     sess.common.get_mut_key_schedule().current_client_traffic_secret = write_key;
        // }

        // /* Send our authentication/finished messages.  These are still encrypted
        //  * with our handshake keys. */
        // if st.client_auth.is_some() {
        //     emit_certificate_tls13(st.client_auth.as_mut().unwrap(),
        //                            sess);
        //     emit_certverify_tls13(st.client_auth.as_mut().unwrap(),
        //                           sess)?;
        // }

        /* Now move to our application traffic keys. */

        println!("HANDSHAKE COMPLETED: {} ns", st.handshake.start_time.elapsed().as_nanos());
        let st = st.into_expect_tls13_traffic(fin);
        #[cfg(feature = "quic")]
        {
            if sess.common.protocol == Protocol::Quic {
                let key_schedule = sess.common.key_schedule.as_ref().unwrap();
                sess.common.quic.traffic_secrets = Some(quic::Secrets {
                    client: key_schedule.current_client_traffic_secret.clone(),
                    server: key_schedule.current_server_traffic_secret.clone(),
                });
                return Ok(Box::new(ExpectQUICTraffic(st)));
            }
        }

        Ok(Box::new(st))
    }
}

struct ExpectTLS12Finished {
    handshake: HandshakeDetails,
    ticket: ReceivedTicketDetails,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectTLS12Finished {
    fn into_expect_tls12_traffic(self, fin: verify::FinishedMessageVerified) -> NextState {
        Box::new(ExpectTLS12Traffic {
            _cert_verified: self.cert_verified,
            _sig_verified: self.sig_verified,
            _fin_verified: fin,
        })
    }
}

impl State for ExpectTLS12Finished {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Finished])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let mut st = *self;
        let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

        // Work out what verify_data we expect.
        let vh = sess.common.hs_transcript.get_current_hash();
        let expect_verify_data = sess
            .common
            .secrets
            .as_ref()
            .unwrap()
            .server_verify_data(&vh);

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                sess.common.send_fatal_alert(AlertDescription::DecryptError);
                TLSError::DecryptError
            })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Hash this message too.
        sess.common.hs_transcript.add_message(&m);

        save_session(&mut st.handshake, &mut st.ticket, sess);

        if st.resuming {
            emit_ccs(sess);
            emit_finished(sess);
        }

        sess.common.we_now_encrypting();
        sess.common.start_traffic();
        Ok(st.into_expect_tls12_traffic(fin))
    }
}

// -- Traffic transit state --
struct ExpectTLS12Traffic {
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl State for ExpectTLS12Traffic {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m, &[ContentType::ApplicationData], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, mut m: Message) -> NextStateOrError {
        sess.common
            .take_received_plaintext(m.take_opaque_payload().unwrap());
        Ok(self)
    }
}

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, keyupdates,
// and application data.
struct ExpectTLS13Traffic {
    handshake: HandshakeDetails,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTLS13Traffic {
    fn handle_new_ticket_tls13(
        &mut self,
        sess: &mut ClientSessionImpl,
        m: Message,
    ) -> Result<(), TLSError> {
        let nst = extract_handshake!(m, HandshakePayload::NewSessionTicketTLS13).unwrap();
        let handshake_hash = sess.common.hs_transcript.get_current_hash();
        let resumption_master_secret = sess
            .common
            .get_key_schedule()
            .derive(SecretKind::ResumptionMasterSecret, &handshake_hash);
        let secret = sess
            .common
            .get_key_schedule()
            .derive_ticket_psk(&resumption_master_secret, &nst.nonce.0);

        let mut value = persist::ClientSessionValue::new(
            ProtocolVersion::TLSv1_3,
            sess.common.get_suite_assert().suite,
            &SessionID::empty(),
            nst.ticket.0.clone(),
            secret,
        );
        value.set_times(ticketer::timebase(), nst.lifetime, nst.age_add);

        if let Some(sz) = nst.get_max_early_data_size() {
            value.set_max_early_data_size(sz);
            #[cfg(feature = "quic")]
            {
                if sess.common.protocol == Protocol::Quic {
                    if sz != 0 && sz != 0xffff_ffff {
                        return Err(TLSError::PeerMisbehavedError(
                            "invalid max_early_data_size".into(),
                        ));
                    }
                }
            }
        }

        let key = persist::ClientSessionKey::session_for_dns_name(self.handshake.dns_name.as_ref());
        #[allow(unused_mut)]
        let mut ticket = value.get_encoding();

        #[cfg(feature = "quic")]
        {
            if sess.common.protocol == Protocol::Quic {
                PayloadU16::encode_slice(sess.common.quic.params.as_ref().unwrap(), &mut ticket);
            }
        }

        let worked = sess
            .config
            .session_persistence
            .put(key.get_encoding(), ticket);

        if worked {
            debug!("Ticket saved");
        } else {
            debug!("Ticket not saved");
        }
        Ok(())
    }

    fn handle_key_update(
        &mut self,
        sess: &mut ClientSessionImpl,
        m: Message,
    ) -> Result<(), TLSError> {
        let kur = extract_handshake!(m, HandshakePayload::KeyUpdate).unwrap();
        sess.common
            .process_key_update(kur, SecretKind::ServerApplicationTrafficSecret)
    }
}

impl State for ExpectTLS13Traffic {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(
            m,
            &[ContentType::ApplicationData, ContentType::Handshake],
            &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
        )
    }

    fn handle(
        mut self: Box<Self>,
        sess: &mut ClientSessionImpl,
        mut m: Message,
    ) -> NextStateOrError {
        if m.is_content_type(ContentType::ApplicationData) {
            sess.common
                .take_received_plaintext(m.take_opaque_payload().unwrap());
        } else if m.is_handshake_type(HandshakeType::NewSessionTicket) {
            self.handle_new_ticket_tls13(sess, m)?;
        } else if m.is_handshake_type(HandshakeType::KeyUpdate) {
            self.handle_key_update(sess, m)?;
        }

        Ok(self)
    }
}

#[cfg(feature = "quic")]
pub struct ExpectQUICTraffic(ExpectTLS13Traffic);

#[cfg(feature = "quic")]
impl State for ExpectQUICTraffic {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_message(
            m,
            &[ContentType::Handshake],
            &[HandshakeType::NewSessionTicket],
        )
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        self.0.handle_new_ticket_tls13(sess, m)?;
        Ok(self)
    }
}
