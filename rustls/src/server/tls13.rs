use crate::{Certificate, key_schedule::{KeyScheduleComputesClientFinish, KeyScheduleComputesServerFinish, KeyScheduleTrafficWithServerFinishedPending, hkdf_expand}, sign::webpki_nike_to_sigscheme};
use crate::msgs::enums::{AlertDescription, SignatureScheme, NamedGroup, ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::enums::{Compression, PSKKeyExchangeMode};
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::handshake::HandshakePayload;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::handshake::NewSessionTicketPayloadTLS13;
use crate::msgs::handshake::CertificateEntry;
use crate::msgs::handshake::CertificateExtension;
use crate::msgs::handshake::CertificateStatus;
use crate::msgs::handshake::CertificatePayloadTLS13;
use crate::msgs::handshake::CertificateRequestPayloadTLS13;
use crate::msgs::handshake::CertReqExtension;
use crate::msgs::handshake::ClientHelloPayload;
use crate::msgs::handshake::HelloRetryRequest;
use crate::msgs::handshake::HelloRetryExtension;
use crate::msgs::handshake::ServerHelloPayload;
use crate::msgs::handshake::KeyShareEntry;
use crate::msgs::handshake::SessionID;
use crate::msgs::handshake::ServerExtension;
use crate::msgs::handshake::Random;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::Codec;
use crate::msgs::persist;
use crate::server::ServerSessionImpl;
use crate::key_schedule::{
    KeyScheduleNonSecret,
    KeyScheduleEarly,
    KeyScheduleHandshake,
    KeyScheduleTrafficWithClientFinishedPending,
    KeyScheduleTraffic
};
use crate::cipher;
use crate::verify;
use crate::rand;
use crate::sign;
use crate::suites;
#[cfg(feature = "logging")]
use crate::log::{warn, trace, debug};
use crate::error::TLSError;
use crate::check::check_message;
#[cfg(feature = "quic")]
use crate::{
    quic,
    msgs::handshake::NewSessionTicketExtension,
    session::Protocol
};

use crate::server::common::{HandshakeDetails, ClientCertDetails};
use crate::server::hs;

use oqs::kem::SharedSecret;
use ring::constant_time;

pub struct CompleteClientHelloHandling {
    pub handshake: HandshakeDetails,
    pub done_retry: bool,
    pub send_cert_status: bool,
    pub send_sct: bool,
    pub send_ticket: bool,
}

impl CompleteClientHelloHandling {
    fn check_binder(&self,
                    sess: &mut ServerSessionImpl,
                    client_hello: &Message,
                    psk: &[u8],
                    binder: &[u8])
                    -> bool {
        let binder_plaintext = match client_hello.payload {
            MessagePayload::Handshake(ref hmp) => hmp.get_encoding_for_binder_signing(),
            _ => unreachable!(),
        };

        let suite = sess.common.get_suite_assert();
        let suite_hash = suite.get_hash();
        let handshake_hash = self.handshake.transcript.get_hash_given(suite_hash, &binder_plaintext);

        let key_schedule = KeyScheduleEarly::new(suite.hkdf_algorithm, &psk);
        let real_binder = key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

        constant_time::verify_slices_are_equal(&real_binder, binder).is_ok()
    }

    fn into_expect_retried_client_hello(self) -> hs::NextState {
        Box::new(hs::ExpectClientHello {
            handshake: self.handshake,
            done_retry: true,
            send_cert_status: self.send_cert_status,
            send_sct: self.send_sct,
            send_ticket: self.send_ticket,
        })
    }

    fn into_expect_certificate(self, key_schedule: ExpectCertificateKeySchedule) -> hs::NextState {
        Box::new(ExpectCertificate {
            handshake: self.handshake,
            key_schedule,
            send_ticket: self.send_ticket,
        })
    }

    fn into_expect_finished(self, key_schedule: KeyScheduleTrafficWithClientFinishedPending, is_pdk: bool) -> hs::NextState {
        Box::new(ExpectFinished {
            handshake: self.handshake,
            key_schedule,
            send_ticket: self.send_ticket,
            is_pdk,
        })
    }

    fn into_expect_ciphertext(self, key_schedule: KeyScheduleHandshake, server_key: sign::CertifiedKey, client_auth: bool) -> hs::NextState {
        Box::new(
            ExpectCiphertext {
                handshake: self.handshake,
                server_key,
                key_schedule,
                client_auth,
                send_ticket: self.send_ticket,
            }
        )
    }

    fn emit_server_hello(&mut self,
                         sess: &mut ServerSessionImpl,
                         session_id: &SessionID,
                         share: &KeyShareEntry,
                         chosen_psk_idx: Option<usize>,
                         resuming_psk: Option<&[u8]>,
                         chosen_proactive_ct_cert_hash: Option<PayloadU8>,
                         maybe_key_schedule: Option<KeyScheduleEarly>,
                        )
                           -> Result<KeyScheduleHandshake, TLSError> {
        let mut extensions = Vec::new();

        // Do key exchange
        self.handshake.print_runtime("ENCAPSULATING TO EPHEMERAL");
        let kxr = suites::KeyExchange::encapsulate(share.group, &share.payload.0)
            .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;
        self.handshake.print_runtime("ENCAPSULATED TO EPHEMERAL");

        let kse = KeyShareEntry::new(share.group, kxr.ciphertext.as_ref());
        extensions.push(ServerExtension::KeyShare(kse));
        extensions.push(ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_3));

        if let Some(psk_idx) = chosen_psk_idx {
            extensions.push(ServerExtension::PresharedKey(psk_idx as u16));
        }

        if let Some(cert_hash) = chosen_proactive_ct_cert_hash {
            extensions.push(ServerExtension::ProactiveCiphertextAccepted(cert_hash));
        }

        let sh = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHello,
                payload: HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from_slice(&self.handshake.randoms.server),
                    session_id: *session_id,
                    cipher_suite: sess.common.get_suite_assert().suite,
                    compression_method: Compression::Null,
                    extensions,
                }),
            }),
        };

        hs::check_aligned_handshake(sess)?;

        #[cfg(feature = "quic")]
        let client_hello_hash = self.handshake.transcript
            .get_hash_given(sess.common.get_suite_assert().get_hash(), &[]);

        trace!("sending server hello {:?}", sh);
        self.handshake.transcript.add_message(&sh);
        sess.common.send_msg(sh, false);
        self.handshake.print_runtime("EMITTED SH");

        // Start key schedule
        let suite = sess.common.get_suite_assert();
        let mut key_schedule = if let Some(psk) = resuming_psk {
            let early_key_schedule = KeyScheduleEarly::new(suite.hkdf_algorithm, psk);

            #[cfg(feature = "quic")] {
                if sess.common.protocol == Protocol::Quic {
                    let client_early_traffic_secret = early_key_schedule
                        .client_early_traffic_secret(&client_hello_hash,
                                                     &*sess.config.key_log,
                                                     &self.handshake.randoms.client);
                    // If 0-RTT should be rejected, this will be clobbered by ExtensionProcessing
                    // before the application can see.
                    sess.common.quic.early_secret = Some(client_early_traffic_secret);
                }
            }

            early_key_schedule
                .into_handshake(&kxr.shared_secret)
        } else if let Some(earlyks) = maybe_key_schedule {
            earlyks.into_handshake(&kxr.shared_secret)
        } else {
            KeyScheduleNonSecret::new(suite.hkdf_algorithm)
                .into_handshake(&kxr.shared_secret)
        };

        let handshake_hash = self.handshake.transcript.get_current_hash();
        let write_key = key_schedule
            .server_handshake_traffic_secret(&handshake_hash,
                                             &*sess.config.key_log,
                                             &self.handshake.randoms.client);
        sess.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

        let read_key = key_schedule
            .client_handshake_traffic_secret(&handshake_hash,
                                             &*sess.config.key_log,
                                             &self.handshake.randoms.client);
        sess.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));

        self.handshake.print_runtime("DERIVED HS");

        #[cfg(feature = "quic")] {
            sess.common.quic.hs_secrets = Some(quic::Secrets {
                client: read_key,
                server: write_key,
            });
        }

        Ok(key_schedule)
    }

    fn emit_fake_ccs(&mut self,
                     sess: &mut ServerSessionImpl) {
        if sess.common.is_quic() { return; }
        let m = Message {
            typ: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {})
        };
        sess.common.send_msg(m, false);
    }

    fn emit_hello_retry_request(&mut self,
                                sess: &mut ServerSessionImpl,
                                group: NamedGroup) {
        let mut req = HelloRetryRequest {
            legacy_version: ProtocolVersion::TLSv1_2,
            session_id: SessionID::empty(),
            cipher_suite: sess.common.get_suite_assert().suite,
            extensions: Vec::new(),
        };

        req.extensions.push(HelloRetryExtension::KeyShare(group));
        req.extensions.push(HelloRetryExtension::SupportedVersions(ProtocolVersion::TLSv1_3));

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::HelloRetryRequest,
                payload: HandshakePayload::HelloRetryRequest(req),
            }),
        };

        trace!("Requesting retry {:?}", m);
        self.handshake.transcript.rollup_for_hrr();
        self.handshake.transcript.add_message(&m);
        sess.common.send_msg(m, false);
    }

    fn emit_encrypted_extensions(&mut self,
                                 sess: &mut ServerSessionImpl,
                                 server_key: &mut sign::CertifiedKey,
                                 hello: &ClientHelloPayload,
                                 resumedata: Option<&persist::ServerSessionValue>,
                                 doing_pdk: bool)
                                 -> Result<(), TLSError> {
        let mut ep = hs::ExtensionProcessing::new();
        ep.process_common(sess, Some(server_key), hello, resumedata, &self.handshake, doing_pdk)?;

        self.send_cert_status = ep.send_cert_status;
        self.send_sct = ep.send_sct;

        let ee = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::EncryptedExtensions,
                payload: HandshakePayload::EncryptedExtensions(ep.exts),
            }),
        };

        trace!("sending encrypted extensions {:?}", ee);
        self.handshake.transcript.add_message(&ee);
        sess.common.send_msg(ee, true);
        Ok(())
    }

    fn emit_certificate_req_tls13(&mut self, sess: &mut ServerSessionImpl) -> Result<bool, TLSError> {
        if !sess.config.verifier.offer_client_auth() {
            return Ok(false);
        }

        let mut cr = CertificateRequestPayloadTLS13 {
            context: PayloadU8::empty(),
            extensions: Vec::new(),
        };

        let schemes = sess.config.get_verifier()
            .supported_verify_schemes();
        cr.extensions.push(CertReqExtension::SignatureAlgorithms(schemes.to_vec()));

        let names = sess.config.verifier.client_auth_root_subjects(sess.get_sni())
            .ok_or_else(|| {
                debug!("could not determine root subjects based on SNI");
                sess.common.send_fatal_alert(AlertDescription::AccessDenied);
                TLSError::General("client rejected by client_auth_root_subjects".into())
            })?;

        if !names.is_empty() {
            cr.extensions.push(CertReqExtension::AuthorityNames(names));
        }

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateRequest,
                payload: HandshakePayload::CertificateRequestTLS13(cr),
            }),
        };

        trace!("Sending CertificateRequest {:?}", m);
        self.handshake.transcript.add_message(&m);
        sess.common.send_msg(m, true);
        Ok(true)
    }

    fn emit_certificate_tls13(&mut self,
                              sess: &mut ServerSessionImpl,
                              server_key: &mut sign::CertifiedKey) {
        let mut cert_entries = vec![];
        for cert in server_key.cert.clone() {
            let hash = cert.hash();
            let cert = if sess.cached_certificate_hashes.contains(&hash) {
                log::trace!("Using certificate hash instead of certificate!");
                Certificate(hash)
            } else {
                log::trace!("sending full certificate");
                cert
            };
            let entry = CertificateEntry {
                cert,
                exts: Vec::new(),
            };
            cert_entries.push(entry);
        }

        if let Some(end_entity_cert) = cert_entries.first_mut() {
            // Apply OCSP response to first certificate (we don't support OCSP
            // except for leaf certs).
            if self.send_cert_status {
                if let Some(ocsp) = server_key.take_ocsp() {
                    let cst = CertificateStatus::new(ocsp);
                    end_entity_cert.exts.push(CertificateExtension::CertificateStatus(cst));
                }
            }

            // Likewise, SCT
            if self.send_sct {
                if let Some(sct_list) = server_key.take_sct_list() {
                    end_entity_cert.exts.push(CertificateExtension::make_sct(sct_list));
                }
            }
        }

        let cert_body = CertificatePayloadTLS13::new(cert_entries);
        let c = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Certificate,
                payload: HandshakePayload::CertificateTLS13(cert_body),
            }),
        };

        trace!("sending certificate {:?}", c);
        self.handshake.print_runtime("EMITTED CERTIFICATE");
        self.handshake.transcript.add_message(&c);
        sess.common.send_msg(c, true);
    }

    fn emit_certificate_verify_tls13(&mut self,
                                     sess: &mut ServerSessionImpl,
                                     server_key: &mut sign::CertifiedKey,
                                     schemes: &[SignatureScheme],
                                     chosen_share: &KeyShareEntry,
                                     key_schedule: &KeyScheduleHandshake,
                                    )
                                     -> Result<(), TLSError> {
        let message = verify::construct_tls13_server_verify_message(
            &self.handshake.transcript.get_current_hash()
        );

        let eecert = webpki::EndEntityCert::from(&server_key.cert[0].0)
            .map_err(TLSError::WebPKIError)?;
        let (scheme, sig) = if eecert.is_nike_cert() {
            use ring::{hkdf, hmac};

            let scheme = eecert.nike_public_key().unwrap().0;
            let nikealg = scheme.alg;
            let scheme = webpki_nike_to_sigscheme(scheme);
            let private_key = server_key.key.get_bytes();
            let ss = match nikealg {
                webpki::NikeImpl::SecSidh(secsidhalg) => {
                    let private_key = secsidh::SecretKey::from_bytes(secsidhalg, private_key).unwrap();
                    let public_key = secsidh::PublicKey::from_bytes(secsidhalg, &chosen_share.payload.0).unwrap();

                    secsidh::derive(&public_key, &private_key).unwrap()
                },
                webpki::NikeImpl::Ctidh(webpki::CtidhAlg::ctidh512) => {
                    use csidh_rust::ctidh512::*;
                    let private_key = CSIDHPrivateKey::from_bytes(private_key);
                    let public_key = CSIDHPublicKey::from_bytes(&chosen_share.payload.0);
                    agreement(&public_key, &private_key).to_vec()
                },
                webpki::NikeImpl::Ctidh(webpki::CtidhAlg::ctidh1024) => {
                    use csidh_rust::ctidh1024::*;
                    let private_key = CSIDHPrivateKey::from_bytes(private_key);
                    let public_key = CSIDHPublicKey::from_bytes(&chosen_share.payload.0);
                    agreement(&public_key, &private_key).to_vec()
                }
            };


            // derive xSS and compute as finished as per https://datatracker.ietf.org/doc/html/draft-ietf-tls-semistatic-dh-01#section-5
            let key = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]).extract(ss.as_ref());

            let hmacalg = key_schedule.hmac_algorithm();
            let hmackey = hkdf_expand(&key, hmacalg, "tls13 finished".as_bytes(), &[]);

            let sig = hmac::sign(&hmackey, &self.handshake.transcript.get_current_hash()).as_ref().to_vec();
            (scheme, sig)
        } else {
            let signing_key = &server_key.key;
            let signer = signing_key.choose_scheme(schemes)
                .ok_or_else(|| hs::incompatible(sess, "no overlapping sigschemes"))?;

            let scheme = signer.get_scheme();
            let sig = signer.sign(&message)?;
            (scheme, sig)
        };

        let cv = DigitallySignedStruct::new(scheme, sig);

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateVerify,
                payload: HandshakePayload::CertificateVerify(cv),
            }),
        };

        trace!("sending certificate-verify {:?}", m);
        self.handshake.transcript.add_message(&m);
        self.handshake.print_runtime("EMITTING CERTV");
        sess.common.send_msg(m, true);
        Ok(())
    }

    fn emit_finished_tls13(&mut self, sess: &mut ServerSessionImpl,
                           key_schedule: KeyScheduleHandshake) -> KeyScheduleTrafficWithClientFinishedPending {
        let handshake_hash = self.handshake.transcript.get_current_hash();
        let verify_data = key_schedule.sign_server_finish(&handshake_hash);
        let verify_data_payload = Payload::new(verify_data);

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };

        trace!("sending finished {:?}", m);
        self.handshake.transcript.add_message(&m);
        self.handshake.hash_at_server_fin = self.handshake.transcript.get_current_hash();
        sess.common.send_msg(m, true);

        // Now move to application data keys.  Read key change is deferred until
        // the Finish message is received & validated.
        let mut key_schedule_traffic = key_schedule.into_traffic_with_client_finished_pending();
        let suite = sess.common.get_suite_assert();
        let write_key = key_schedule_traffic
            .server_application_traffic_secret(&self.handshake.hash_at_server_fin,
                                               &*sess.config.key_log,
                                               &self.handshake.randoms.client);
        sess.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

        key_schedule_traffic
            .exporter_master_secret(&self.handshake.hash_at_server_fin,
                                    &*sess.config.key_log,
                                    &self.handshake.randoms.client);

        let _read_key = key_schedule_traffic
            .client_application_traffic_secret(&self.handshake.hash_at_server_fin,
                                               &*sess.config.key_log,
                                               &self.handshake.randoms.client);

        #[cfg(feature = "quic")] {
            sess.common.quic.traffic_secrets = Some(quic::Secrets {
                client: _read_key,
                server: write_key,
            });
        }

        key_schedule_traffic
    }

    fn attempt_tls13_ticket_decryption(&mut self,
                                       sess: &mut ServerSessionImpl,
                                       ticket: &[u8]) -> Option<persist::ServerSessionValue> {
        if sess.config.ticketer.enabled() {
            sess.config
                .ticketer
                .decrypt(ticket)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
        } else {
            sess.config
                .session_storage
                .take(ticket)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
        }
    }

    pub fn handle_client_hello(mut self,
                               sess: &mut ServerSessionImpl,
                               server_key: sign::CertifiedKey,
                               chm: &Message) -> hs::NextStateOrError {
        let client_hello = require_handshake_msg!(chm, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;

        if client_hello.compression_methods.len() != 1 {
            return Err(hs::illegal_param(sess, "client offered wrong compressions"));
        }

        let groups_ext = client_hello.get_namedgroups_extension()
            .ok_or_else(|| hs::incompatible(sess, "client didn't describe groups"))?;

        let mut sigschemes_ext = client_hello.get_sigalgs_extension()
            .ok_or_else(|| hs::incompatible(sess, "client didn't describe sigschemes"))?
            .clone();

        let tls13_schemes = sign::supported_sign_tls13();
        sigschemes_ext.retain(|scheme| tls13_schemes.contains(scheme));

        let shares_ext = client_hello.get_keyshare_extension()
            .ok_or_else(|| hs::incompatible(sess, "client didn't send keyshares"))?;

        if client_hello.has_keyshare_extension_with_duplicates() {
            return Err(hs::illegal_param(sess, "client sent duplicate keyshares"));
        }

        let share_groups: Vec<NamedGroup> = shares_ext.iter()
            .map(|share| share.group)
            .collect();

        let supported_groups = suites::KeyExchange::supported_groups();
        let chosen_group = supported_groups
            .iter()
            .filter(|group| share_groups.contains(group))
            .nth(0)
            .cloned();

        // we need to decide here if our certificate is a NIKE and the group matches it.
        let eecrt = &server_key.cert[0];
        let eecert = webpki::EndEntityCert::from(&eecrt.0)
            .map_err(TLSError::WebPKIError)?;
        let is_nike = eecert.is_nike_cert();
        let group_doesnt_match_for_optls = if is_nike && chosen_group.is_some() {
            let sigalg = webpki_nike_to_sigscheme(eecert.nike_public_key().unwrap().0);
            let named_group = chosen_group.unwrap();
            let algs_match = include!("../generated/nikealgs_match.rs");
            !algs_match
        } else {
            false
        };

        if chosen_group.is_none() || group_doesnt_match_for_optls {
            if group_doesnt_match_for_optls {
                todo!("need to implement filtering on offered groups based on certificate.");
            }
            // We don't have a suitable key share.  Choose a suitable group and
            // send a HelloRetryRequest.
            let retry_group_maybe = supported_groups
                .iter()
                .filter(|group| groups_ext.contains(group))
                .nth(0)
                .cloned();
            self.handshake.transcript.add_message(chm);

            if let Some(group) = retry_group_maybe {
                if self.done_retry {
                    return Err(hs::illegal_param(sess, "did not follow retry request"));
                }

                self.emit_hello_retry_request(sess, group);
                self.emit_fake_ccs(sess);
                return Ok(self.into_expect_retried_client_hello());
            }

            return Err(hs::incompatible(sess, "no kx group overlap with client"));
        }

        let chosen_group = chosen_group.unwrap();
        let chosen_share = shares_ext.iter()
            .find(|share| share.group == chosen_group)
            .unwrap();

        let mut chosen_psk_index = None;
        let mut resumedata = None;
        if let Some(psk_offer) = client_hello.get_psk() {
            if !client_hello.check_psk_ext_is_last() {
                return Err(hs::illegal_param(sess, "psk extension in wrong position"));
            }

            if psk_offer.binders.is_empty() {
                return Err(hs::decode_error(sess, "psk extension missing binder"));
            }

            if psk_offer.binders.len() != psk_offer.identities.len() {
                return Err(hs::illegal_param(sess, "psk extension mismatched ids/binders"));
            }

            for (i, psk_id) in psk_offer.identities.iter().enumerate() {
                let maybe_resume = self.attempt_tls13_ticket_decryption(sess, &psk_id.identity.0);

                if !hs::can_resume(sess, &self.handshake, &maybe_resume) {
                    continue;
                }

                let resume = maybe_resume.unwrap();

                if !self.check_binder(sess, chm, &resume.master_secret.0, &psk_offer.binders[i].0) {
                    sess.common.send_fatal_alert(AlertDescription::DecryptError);
                    return Err(TLSError::PeerMisbehavedError("client sent wrong binder".to_string()));
                }

                chosen_psk_index = Some(i);
                resumedata = Some(resume);
                break;
            }
        }

        if !client_hello.psk_mode_offered(PSKKeyExchangeMode::PSK_DHE_KE) {
            debug!("Client unwilling to resume, DHE_KE not offered");
            self.send_ticket = false;
            chosen_psk_index = None;
            resumedata = None;
        } else {
            self.send_ticket = true;
        }

        // figure out PDK
        let doing_pdk = server_key
            .end_entity_cert()
            .and_then(|crt| client_hello.get_proactive_ciphertext(crt).ok_or(()));

        let mut proactive_static_shared_secret = None;
        let mut proactive_ss_certificate_hash = None;
        if chosen_psk_index.is_none() {
            if let Ok(offer) = doing_pdk {
                let eecrt = webpki::EndEntityCert::from(server_key.cert[0].as_ref()).unwrap();
                // accept KEMTLS-PDK
                proactive_ss_certificate_hash = Some(offer.certificate_hash.clone());
                self.handshake.print_runtime("PDK DECAPSULATING FROM CERTIFICATE");
                let ss = eecrt
                        .decapsulate(server_key.key.get_bytes(), offer.ciphertext.0.as_ref())
                        .unwrap();
                self.handshake.print_runtime("PDK DECAPSULATED FROM CERTIFICATE");
                proactive_static_shared_secret = Some(ss);
            };
        };
        let suite = sess.common.get_suite_assert();
        let maybe_key_schedule = proactive_static_shared_secret
            .map(|ss| KeyScheduleEarly::new(suite.hkdf_algorithm, &ss));
        let doing_pdk = doing_pdk.is_ok();
        let pdk_client_auth = doing_pdk && client_hello.find_extension(crate::msgs::enums::ExtensionType::ProactiveClientAuth).is_some();

        if let Some(ref resume) = resumedata {
            sess.received_resumption_data = Some(resume.application_data.0.clone());
            sess.client_cert_chain = resume.client_cert_chain.clone();
        }

        let full_handshake = resumedata.is_none();
        debug!("PSK DEBUG: full_handshake={}, resumedata.is_some()={}, chosen_psk_index={:?}",
               full_handshake, resumedata.is_some(), chosen_psk_index);
        self.handshake.transcript.add_message(chm);

        if let Some(ref ks) = maybe_key_schedule {
            let read_key = ks.client_early_traffic_secret(
                &self.handshake.transcript.get_current_hash(),
                &*sess.config.key_log,
                &self.handshake.randoms.client);
            sess.common
                .record_layer
                .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
        }

        if pdk_client_auth {
            Ok(Box::new(ExpectPDKCertificate {
                expect_hello: self,
                client_hello: client_hello.to_owned(),
                server_key,
                key_schedule: maybe_key_schedule,
                chosen_share: chosen_share.clone(),
                chosen_psk_index,
                resumedata,
                proactive_ss_certificate_hash,
                pdk_client_auth,
                full_handshake,
                doing_pdk,
                sigschemes_ext,
            }))
        } else {
            self.complete_handle_client_hello(sess, server_key, client_hello, maybe_key_schedule, chosen_share, chosen_psk_index, resumedata, proactive_ss_certificate_hash, pdk_client_auth, full_handshake, doing_pdk, sigschemes_ext, None)
        }
    }

    pub fn complete_handle_client_hello(mut self,
                sess: &mut ServerSessionImpl,
                mut server_key: sign::CertifiedKey,
                client_hello: &ClientHelloPayload,
                key_schedule: Option<KeyScheduleEarly>,
                chosen_share: &KeyShareEntry,
                chosen_psk_index: Option<usize>,
                resumedata: Option<persist::ServerSessionValue>,
                proactive_ss_certificate_hash: Option<PayloadU8>,
                pdk_client_auth: bool,
                full_handshake: bool,
                doing_pdk: bool,
                sigschemes_ext: Vec<SignatureScheme>,
                cert: Option<ClientCertDetails>,
            ) -> hs::NextStateOrError {

        // split
        let key_schedule = self.emit_server_hello(sess, &client_hello.session_id,
                                                  chosen_share, chosen_psk_index,
                                                  resumedata.as_ref().map(|x| &x.master_secret.0[..]),
                                                  proactive_ss_certificate_hash,
                                                  key_schedule,
                                                )?;
        if !self.done_retry {
            self.emit_fake_ccs(sess);
        }
        self.emit_encrypted_extensions(sess, &mut server_key, client_hello, resumedata.as_ref(), doing_pdk)?;

        debug!("PSK DEBUG: About to check certificate sending - full_handshake={}", full_handshake);
        let (doing_client_auth, is_kemtls) = if full_handshake {
            debug!("PSK DEBUG: Entering full_handshake branch - WILL SEND CERTIFICATE");
            let client_auth;
            let is_kemtls = if !doing_pdk {
                client_auth = self.emit_certificate_req_tls13(sess)?;
                self.emit_certificate_tls13(sess, &mut server_key);            // determine if kemtls
                webpki::EndEntityCert::from(&server_key.end_entity_cert().unwrap().0)
                    .map(|crt| crt.is_kem_cert(),)
                    .map_err(|e| TLSError::WebPKIError(e))?
            } else {
                client_auth = pdk_client_auth;
                true // pdk is always kemtls
            };
            if !is_kemtls {
                self.emit_certificate_verify_tls13(sess,
                    &mut server_key, &sigschemes_ext,
                    chosen_share, &key_schedule)?;
            }
            (client_auth, is_kemtls)
        } else {
            debug!("PSK DEBUG: Entering PSK resumption branch - SKIPPING CERTIFICATE");
            (false, false)
        };

        if is_kemtls && !doing_pdk {
            Ok(self.into_expect_ciphertext(key_schedule, server_key, doing_client_auth))
        } else if is_kemtls && doing_pdk {
            hs::check_aligned_handshake(sess)?;
            if doing_client_auth {
                let mandatory = sess.config.verifier.client_auth_mandatory(sess.get_sni())
                .ok_or_else(|| {
                    debug!("could not determine if client auth is mandatory based on SNI");
                    sess.common.send_fatal_alert(AlertDescription::AccessDenied);
                    TLSError::General("client rejected by client_auth_mandatory".into())
                })?;
                if mandatory && cert.is_none() {
                    sess.common.send_fatal_alert(AlertDescription::CertificateRequired);
                    return Err(TLSError::NoCertificatesPresented);
                }
                let cert = cert.unwrap();
                // emit ciphertext XXX copied from ExpectCertificate.emit_ciphertext
                let certificate = webpki::EndEntityCert::from(&cert.cert_chain[0].0)
                    .map_err(TLSError::WebPKIError)?;
                self.handshake.print_runtime("PDK ENCAPSULATING TO CCERT");
                let (ct, ss) = certificate.encapsulate().map_err(|_| TLSError::DecryptError)?;
                self.handshake.print_runtime("PDK ENCAPSULATED TO CCERT");
                let m = Message {
                    typ: ContentType::Handshake,
                    version: ProtocolVersion::TLSv1_3,
                    payload: MessagePayload::Handshake(HandshakeMessagePayload {
                        typ: HandshakeType::ClientKemCiphertext,
                        payload: HandshakePayload::ClientKemCiphertext(Payload::new(ct.into_vec())),
                    }),
                };
                self.handshake.transcript.add_message(&m);
                sess.common.send_msg(m, true);

                let ks = emit_finished_kemtlspdk(&mut self.handshake, sess, key_schedule, Some(ss.as_ref()));
                Ok(self.into_expect_finished(ks, true))
            } else {
                trace!("Not doing client auth with PDK ");
                let key_schedule_traffic = emit_finished_kemtlspdk(&mut self.handshake, sess, key_schedule, None);
                Ok(self.into_expect_finished(key_schedule_traffic, true))
            }
        } else {
            hs::check_aligned_handshake(sess)?;
            let key_schedule_traffic = self.emit_finished_tls13(sess, key_schedule);

            if doing_client_auth {
                Ok(self.into_expect_certificate(ExpectCertificateKeySchedule::TLS13(key_schedule_traffic)))
            } else {
                self.handshake.print_runtime("WRITING TO CLIENT");
                //sess.common.start_traffic(); // this breaks
                Ok(self.into_expect_finished(key_schedule_traffic, false))
            }
        }
    }
}

/// Used to postpone sending SH until we've received the Cert
struct ExpectPDKCertificate {
    expect_hello: CompleteClientHelloHandling,
    client_hello: ClientHelloPayload,
    server_key: sign::CertifiedKey,
    key_schedule: Option<KeyScheduleEarly>,
    chosen_share: KeyShareEntry,
    chosen_psk_index: Option<usize>,
    resumedata: Option<persist::ServerSessionValue>,
    proactive_ss_certificate_hash: Option<PayloadU8>,
    pdk_client_auth: bool,
    full_handshake: bool,
    doing_pdk: bool,
    sigschemes_ext: Vec<SignatureScheme>,
}

impl ExpectPDKCertificate {
    fn finish_handle_clienthello(self, sess: &mut ServerSessionImpl, cert: ClientCertDetails) -> hs::NextStateOrError {
        self.expect_hello.complete_handle_client_hello(
            sess,
            self.server_key,
            &self.client_hello,
            self.key_schedule,
            &self.chosen_share,
            self.chosen_psk_index,
            self.resumedata,
            self.proactive_ss_certificate_hash,
            self.pdk_client_auth,
            self.full_handshake,
            self.doing_pdk,
            self.sigschemes_ext,
            Some(cert),
        )
    }
}

impl hs::State for ExpectPDKCertificate {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let certp = require_handshake_msg!(m, HandshakeType::Certificate, HandshakePayload::CertificateTLS13)?;
        trace!("Received PDK certificate");
        self.expect_hello.handshake.transcript.add_message(&m);

        // We don't send any CertificateRequest extensions, so any extensions
        // here are illegal.
        if certp.any_entry_has_extension() {
            return Err(TLSError::PeerMisbehavedError("client sent unsolicited cert extension"
                                                     .to_string()));
        }

        let cert_chain = certp.convert();

        if cert_chain.is_empty() {
            sess.common.send_fatal_alert(AlertDescription::CertificateRequired);
            return Err(TLSError::NoCertificatesPresented);
        }

        sess.config.get_verifier().verify_client_cert(&cert_chain, sess.get_sni())
            .or_else(|err| {
                     hs::incompatible(sess, "certificate invalid");
                     Err(err)
                    })?;

        let cert = ClientCertDetails::new(cert_chain);

        self.finish_handle_clienthello(sess, cert)
    }
}


fn emit_finished_kemtlspdk(
    handshake: &mut HandshakeDetails, sess: &mut ServerSessionImpl, key_schedule: KeyScheduleHandshake,
    ss: Option<&[u8]>
) -> KeyScheduleTrafficWithClientFinishedPending {
    let handshake_hash = handshake.transcript.get_current_hash();
    let mut key_schedule = key_schedule.into_kemtlspdk_traffic_with_client_finished_pending(ss);
    let verify_data = key_schedule.sign_server_finished_kemtlspdk(&handshake_hash);
    let verify_data_payload = Payload::new(verify_data);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    trace!("sending kemtlspdk finished {:?}", m);
    handshake.transcript.add_message(&m);
    handshake.hash_at_server_fin = handshake.transcript.get_current_hash();
    sess.common.send_msg(m, true);

    // Now move to application data keys.  Read key change is deferred until
    // the Finish message is received & validated.
    let suite = sess.common.get_suite_assert();
    let write_key = key_schedule
        .server_application_traffic_secret(&handshake.hash_at_server_fin,
                                           &*sess.config.key_log,
                                           &handshake.randoms.client);
    sess.common
        .record_layer
        .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

    handshake.print_runtime("WRITING TO CLIENT");
    //sess.common.start_traffic(); // breaks

    #[cfg(feature = "quic")] {
        sess.common.quic.traffic_secrets = Some(quic::Secrets {
            client: _read_key,
            server: write_key,
        });
    }

    key_schedule
}

pub struct ExpectCiphertext {
    handshake: HandshakeDetails,
    key_schedule: KeyScheduleHandshake,
    client_auth: bool,
    server_key: sign::CertifiedKey,
    send_ticket: bool,
}

impl ExpectCiphertext {
    fn into_expect_certificate(self) -> hs::NextState {
        Box::new(ExpectCertificate {
            handshake: self.handshake,
            key_schedule: ExpectCertificateKeySchedule::KEMTLS(self.key_schedule),
            send_ticket: self.send_ticket,
        })
    }

    fn into_expect_finished(self) -> hs::NextState {
        Box::new(ExpectKEMTLSFinished {
            handshake: self.handshake,
            key_schedule: self.key_schedule.into_traffic_with_server_finished_pending(None),
            send_ticket: self.send_ticket,
        })
    }

}

impl hs::State for ExpectCiphertext {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let ctmsg = require_handshake_msg!(m, HandshakeType::ServerKemCiphertext, HandshakePayload::ServerKemCiphertext)?;
        self.handshake.print_runtime("RECEIVED CKEX");

        // decapsulate
        let ciphertext = &ctmsg.0;
        let eecrt = self.server_key.end_entity_cert()
        .map_err(|_| TLSError::NoCertificatesPresented)
        .and_then(|crt| webpki::EndEntityCert::from(&crt.0).map_err(TLSError::WebPKIError))?;

        self.handshake.print_runtime("DECAPSULATING FROM CERTIFICATE");
        let ss = eecrt.decapsulate(self.server_key.key.get_bytes(), ciphertext).map_err(TLSError::WebPKIError)?;
        self.handshake.print_runtime("DECAPSULATED FROM CERTIFICATE");

        // add message to transcript
        self.handshake.transcript.add_message(&m);

        // upgrade to authenticated handshake secret
        self.key_schedule.authenticate_handshake(&ss);

        let hs_hash = self.handshake.transcript.get_current_hash();

        // derive new secret keys
        let read_key = self.key_schedule.client_authenticated_handshake_traffic_secret(
            &hs_hash,
            &*sess.config.key_log,
            &self.handshake.randoms.client);
        let write_key = self.key_schedule.server_authenticated_handshake_traffic_secret(
            &hs_hash,
            &*sess.config.key_log,
            &self.handshake.randoms.client);

        let suite = sess.common.get_suite_assert();
        sess.common.record_layer.set_message_encrypter(cipher::new_tls13_write(&suite, &write_key));
        sess.common.record_layer.set_message_decrypter(cipher::new_tls13_read(&suite, &read_key));

        self.handshake.print_runtime("DERIVED AHS");

        // move on to the next phase
        if self.client_auth {
            Ok(self.into_expect_certificate())
        } else {
            Ok(self.into_expect_finished())
        }
    }
}

pub enum ExpectCertificateKeySchedule {
    TLS13(KeyScheduleTrafficWithClientFinishedPending),
    KEMTLS(KeyScheduleHandshake),
}

impl ExpectCertificateKeySchedule {
    fn tls13(self) -> KeyScheduleTrafficWithClientFinishedPending {
        use ExpectCertificateKeySchedule::*;
        match self {
            TLS13(x) => x,
            _ => panic!("Wrong type!"),
        }
    }

    fn kemtls(self) -> KeyScheduleHandshake {
        use ExpectCertificateKeySchedule::*;
        match self {
            KEMTLS(x) => x,
            _ => panic!("Wrong type!"),
        }
    }

    fn is_kemtls(&self) -> bool {
        match self {
            ExpectCertificateKeySchedule::KEMTLS(_) => true,
            _ => false,
        }
    }
}

pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub key_schedule: ExpectCertificateKeySchedule,
    pub send_ticket: bool,
}

impl ExpectCertificate {
    fn into_expect_finished(self) -> hs::NextState {
        let ks = self.key_schedule.tls13();
        Box::new(ExpectFinished {
            key_schedule: ks,
            handshake: self.handshake,
            send_ticket: self.send_ticket,
            is_pdk: false,
        })
    }

    fn into_expect_certificate_verify(self,
                                      cert: ClientCertDetails) -> hs::NextState {
        Box::new(ExpectCertificateVerify {
            handshake: self.handshake,
            key_schedule: self.key_schedule.tls13(),
            client_cert: cert,
            send_ticket: self.send_ticket,
        })
    }

    fn emit_ciphertext(&mut self, sess: &mut ServerSessionImpl, cert: ClientCertDetails) -> Result<SharedSecret, TLSError> {
        let certificate = webpki::EndEntityCert::from(&cert.cert_chain[0].0)
            .map_err(TLSError::WebPKIError)?;
        self.handshake.print_runtime("ENCAPSULATING TO CLIENT");
        let (ct, ss) = certificate.encapsulate().map_err(|_| TLSError::DecryptError)?;
        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientKemCiphertext,
                payload: HandshakePayload::ClientKemCiphertext(Payload::new(ct.into_vec())),
            }),
        };
        self.handshake.transcript.add_message(&m);
        sess.common.send_msg(m, true);
        self.handshake.print_runtime("SUBMITTED SKEX TO CLIENT");

        Ok(ss)
    }

    fn into_expect_kemtls_finished(self, ss: SharedSecret) -> hs::NextStateOrError {
        Ok(Box::new(ExpectKEMTLSFinished {
            key_schedule: self.key_schedule.kemtls().into_traffic_with_server_finished_pending(Some(ss.as_ref())),
            send_ticket: false,
            handshake: self.handshake,
        }))
    }

}

impl hs::State for ExpectCertificate {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let certp = require_handshake_msg!(m, HandshakeType::Certificate, HandshakePayload::CertificateTLS13)?;
        self.handshake.transcript.add_message(&m);
        self.handshake.print_runtime("RECEIVED CERTIFICATE");

        // We don't send any CertificateRequest extensions, so any extensions
        // here are illegal.
        if certp.any_entry_has_extension() {
            return Err(TLSError::PeerMisbehavedError("client sent unsolicited cert extension"
                                                     .to_string()));
        }

        let cert_chain = certp.convert();

        let mandatory = sess.config.verifier.client_auth_mandatory(sess.get_sni())
            .ok_or_else(|| {
                debug!("could not determine if client auth is mandatory based on SNI");
                sess.common.send_fatal_alert(AlertDescription::AccessDenied);
                TLSError::General("client rejected by client_auth_mandatory".into())
            })?;

        if cert_chain.is_empty() {
            if !mandatory {
                debug!("client auth requested but no certificate supplied");
                self.handshake.transcript.abandon_client_auth();
                return Ok(self.into_expect_finished());
            }

            sess.common.send_fatal_alert(AlertDescription::CertificateRequired);
            return Err(TLSError::NoCertificatesPresented);
        }

        if self.key_schedule.is_kemtls() {
            let cert = ClientCertDetails::new(cert_chain);
            let ss = self.emit_ciphertext(sess, cert)?;
            self.into_expect_kemtls_finished(ss)
        } else {
            sess.config.get_verifier().verify_client_cert(&cert_chain, sess.get_sni())
                .or_else(|err| {
                     hs::incompatible(sess, "certificate invalid");
                     Err(err)
                    })?;
            let cert = ClientCertDetails::new(cert_chain);

            Ok(self.into_expect_certificate_verify(cert))
        }
    }
}

pub struct ExpectCertificateVerify {
    handshake: HandshakeDetails,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    client_cert: ClientCertDetails,
    send_ticket: bool,
}

impl ExpectCertificateVerify {
    fn into_expect_finished(self) -> hs::NextState {
        Box::new(ExpectFinished {
            key_schedule: self.key_schedule,
            handshake: self.handshake,
            send_ticket: self.send_ticket,
            is_pdk: false,
        })
    }
}

impl hs::State for ExpectCertificateVerify {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let rc = {
            let sig = require_handshake_msg!(m, HandshakeType::CertificateVerify, HandshakePayload::CertificateVerify)?;
            self.handshake.print_runtime("RECEIVED CERTV");
            let handshake_hash = self.handshake.transcript.get_current_hash();
            self.handshake.transcript.abandon_client_auth();
            let certs = &self.client_cert.cert_chain;
            let msg = verify::construct_tls13_client_verify_message(&handshake_hash);

            sess.config
                .get_verifier()
                .verify_tls13_signature(&msg,
                                        &certs[0],
                                        sig)
        };

        if let Err(e) = rc {
            sess.common.send_fatal_alert(AlertDescription::AccessDenied);
            return Err(e);
        }

        self.handshake.print_runtime("AUTHENTICATED CLIENT");

        trace!("client CertificateVerify OK");
        sess.client_cert_chain = Some(self.client_cert.take_chain());

        self.handshake.transcript.add_message(&m);
        Ok(self.into_expect_finished())
    }
}

// --- Process client's Finished ---
fn get_server_session_value(handshake: &mut HandshakeDetails,
                            key_schedule: &KeyScheduleTraffic,
                            sess: &ServerSessionImpl,
                            nonce: &[u8]) -> persist::ServerSessionValue {
    let scs = sess.common.get_suite_assert();
    let version = ProtocolVersion::TLSv1_3;

    let handshake_hash = handshake
        .transcript
        .get_current_hash();
    let secret = key_schedule
        .resumption_master_secret_and_derive_ticket_psk(&handshake_hash, nonce);

    persist::ServerSessionValue::new(
        sess.get_sni(), version,
        scs.suite, secret,
        &sess.client_cert_chain,
        sess.alpn_protocol.clone(),
        sess.resumption_data.clone(),
    )
}

pub struct ExpectKEMTLSFinished {
    pub handshake: HandshakeDetails,
    key_schedule: KeyScheduleTrafficWithServerFinishedPending,
    send_ticket: bool,
}

impl ExpectKEMTLSFinished {
}

impl hs::State for ExpectKEMTLSFinished {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let finished = require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;
        trace!("Received KEMTLS finished");
        self.handshake.print_runtime("RECEIVED FINISHED");

        let handshake_hash = self.handshake.transcript.get_current_hash();
        let expect_verify_data = self.key_schedule.sign_client_finish(&handshake_hash);

        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                     sess.common.send_fatal_alert(AlertDescription::DecryptError);
                     warn!("Finished wrong");
                     TLSError::DecryptError
                     })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        self.handshake.transcript.add_message(&m);

        // Install keying to read future messages.
        let read_key = self.key_schedule
            .client_application_traffic_secret(&self.handshake.transcript.get_current_hash(),
                                                &*sess.config.key_log,
                                                &self.handshake.randoms.client);

        let handshake_hash = self.handshake.transcript.get_current_hash();
        let verify_data = self.key_schedule.sign_server_finish(&handshake_hash);
        let verify_data_payload = Payload::new(verify_data);

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };

        let suite = sess.common.get_suite_assert();

        sess.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));

        trace!("sending finished {:?}", m);
        self.handshake.transcript.add_message(&m);
        self.handshake.hash_at_server_fin = self.handshake.transcript.get_current_hash();
        sess.common.send_msg(m, true);
        self.handshake.print_runtime("EMITTED FINISHED");


        let write_key = self.key_schedule
            .server_application_traffic_secret(&self.handshake.hash_at_server_fin,
                                               &*sess.config.key_log,
                                               &self.handshake.randoms.client);

        sess.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

        self.key_schedule
            .exporter_master_secret(&self.handshake.hash_at_server_fin,
                                    &*sess.config.key_log,
                                    &self.handshake.randoms.client);

        let key_schedule_traffic = self.key_schedule.into_traffic();

        if self.send_ticket {
            if sess.config.ticketer.enabled() {
                emit_stateless_ticket(&mut self.handshake, sess, &key_schedule_traffic);
            } else {
                emit_stateful_ticket(&mut self.handshake, sess, &key_schedule_traffic);
            }
        }
        self.handshake.print_runtime("READING TRAFFIC");
        self.handshake.print_runtime("HANDSHAKE COMPLETED");
        sess.common.start_traffic();

        Ok(Box::new(ExpectTraffic {
            _fin_verified: fin,
            key_schedule: key_schedule_traffic,
            want_write_key_update: false,
        }))
    }
}

pub struct ExpectFinished {
    pub handshake: HandshakeDetails,
    pub key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    pub send_ticket: bool,
    pub is_pdk: bool,
}

impl ExpectFinished {
    fn into_expect_traffic(fin: verify::FinishedMessageVerified, ks: KeyScheduleTraffic) -> hs::NextState {
        Box::new(ExpectTraffic {
            key_schedule: ks,
            want_write_key_update: false,
            _fin_verified: fin,
        })
    }
}

fn emit_stateless_ticket(handshake: &mut HandshakeDetails,
                            sess: &mut ServerSessionImpl,
                            key_schedule: &KeyScheduleTraffic) {
    let nonce = rand::random_vec(32);
    let plain = get_server_session_value(handshake,
                                            key_schedule,
                                            sess, &nonce)
        .get_encoding();
    let maybe_ticket = sess.config
        .ticketer
        .encrypt(&plain);
    let ticket_lifetime = sess.config.ticketer.get_lifetime();

    if maybe_ticket.is_none() {
        return;
    }

    let ticket = maybe_ticket.unwrap();
    let age_add = rand::random_u32(); // nb, we don't do 0-RTT data, so whatever
    #[allow(unused_mut)]
    let mut payload = NewSessionTicketPayloadTLS13::new(ticket_lifetime, age_add, nonce, ticket);
    #[cfg(feature = "quic")] {
        if sess.config.max_early_data_size > 0 && sess.common.protocol == Protocol::Quic {
            payload.exts.push(NewSessionTicketExtension::EarlyData(sess.config.max_early_data_size));
        }
    }
    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicketTLS13(payload),
        }),
    };

    trace!("sending new ticket {:?}", m);
    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

fn emit_stateful_ticket(handshake: &mut HandshakeDetails,
                        sess: &mut ServerSessionImpl,
                        key_schedule: &KeyScheduleTraffic) {
    let nonce = rand::random_vec(32);
    let id = rand::random_vec(32);
    let plain = get_server_session_value(handshake,
                                            key_schedule,
                                            sess, &nonce)
        .get_encoding();

    if sess.config.session_storage.put(id.clone(), plain) {
        let stateful_lifetime = 24 * 60 * 60; // this is a bit of a punt
        let age_add = rand::random_u32();
        #[allow(unused_mut)]
        let mut payload = NewSessionTicketPayloadTLS13::new(stateful_lifetime, age_add, nonce, id);
        #[cfg(feature = "quic")] {
            if sess.config.max_early_data_size > 0 && sess.common.protocol == Protocol::Quic {
                payload.exts.push(NewSessionTicketExtension::EarlyData(sess.config.max_early_data_size));
            }
        }
        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::NewSessionTicket,
                payload: HandshakePayload::NewSessionTicketTLS13(payload),
            }),
        };

        trace!("sending new stateful ticket {:?}", m);
        handshake.transcript.add_message(&m);
        sess.common.send_msg(m, true);
    } else {
        trace!("resumption not available; not issuing ticket");
    }
}

impl hs::State for ExpectFinished {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let finished = require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;
        trace!("received Finished");
        self.handshake.print_runtime("RECEIVED FINISHED");

        // nb. future derivations include Client Finished, but not the
        // main application data keying.
        let handshake_hash = if self.is_pdk {
            self.handshake.transcript.get_current_hash()
        } else {
            self.handshake.hash_at_server_fin.clone()
        };

        trace!("Computing CFIN for hash: {:x?}", handshake_hash);

        let expect_verify_data = if self.is_pdk {
            self.key_schedule.sign_client_finished_kemtlspdk(&handshake_hash)
        } else {
            self.key_schedule.sign_client_finish(&handshake_hash)
        };

        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                     sess.common.send_fatal_alert(AlertDescription::DecryptError);
                     warn!("Finished wrong");
                     TLSError::DecryptError
                     })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        self.handshake.transcript.add_message(&m);

        hs::check_aligned_handshake(sess)?;
        trace!("verified CFIN");

        let suite = sess.common.get_suite_assert();

        let traffic_hash = if self.is_pdk {
            self.handshake.transcript.get_current_hash()
        } else {
            self.handshake.hash_at_server_fin.clone()
        };

        // Install keying to read future messages.
        let read_key = self.key_schedule
            .client_application_traffic_secret(&traffic_hash,
                                               &*sess.config.key_log,
                                               &self.handshake.randoms.client);
        trace!("derived read key from hash {:x?}", &traffic_hash);
        sess.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));

        // if we're doing PDK we still need to derive this.
        if self.is_pdk {
            self.key_schedule
                .exporter_master_secret(&traffic_hash,
                                        &*sess.config.key_log,
                                        &self.handshake.randoms.client);
        }

        let key_schedule_traffic = self.key_schedule.into_traffic();

        if self.send_ticket {
            if sess.config.ticketer.enabled() {
                emit_stateless_ticket(&mut self.handshake, sess, &key_schedule_traffic);
            } else {
                emit_stateful_ticket(&mut self.handshake, sess, &key_schedule_traffic);
            }
        }

        self.handshake.print_runtime("READING TRAFFIC");
        self.handshake.print_runtime("HANDSHAKE COMPLETED");
        sess.common.start_traffic();

        #[cfg(feature = "quic")] {
            if sess.common.protocol == Protocol::Quic {
                return Ok(Box::new(ExpectQUICTraffic {
                    key_schedule: key_schedule_traffic,
                    _fin_verified: fin,
                }));
            }
        }

        Ok(Self::into_expect_traffic(fin, key_schedule_traffic))
    }
}

// --- Process traffic ---
pub struct ExpectTraffic {
    key_schedule: KeyScheduleTraffic,
    want_write_key_update: bool,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_traffic(&self, sess: &mut ServerSessionImpl, mut m: Message) -> Result<(), TLSError> {
        sess.common.take_received_plaintext(m.take_opaque_payload().unwrap());
        Ok(())
    }

    fn handle_key_update(&mut self, sess: &mut ServerSessionImpl, kur: &KeyUpdateRequest) -> Result<(), TLSError> {
        #[cfg(feature = "quic")]
        {
            if let Protocol::Quic = sess.common.protocol {
                sess.common.send_fatal_alert(AlertDescription::UnexpectedMessage);
                let msg = "KeyUpdate received in QUIC connection".to_string();
                warn!("{}", msg);
                return Err(TLSError::PeerMisbehavedError(msg));
            }
        }

        hs::check_aligned_handshake(sess)?;

        match kur {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                self.want_write_key_update = true;
            }
            _ => {
                sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
                return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
            }
        }

        // Update our read-side keys.
        let new_read_key = self.key_schedule.next_client_application_traffic_secret();
        let suite = sess.common.get_suite_assert();
        sess.common.record_layer.set_message_decrypter(cipher::new_tls13_read(suite, &new_read_key));

        Ok(())
    }
}

impl hs::State for ExpectTraffic {
    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        if m.is_content_type(ContentType::ApplicationData) {
            self.handle_traffic(sess, m)?;
        } else if let Ok(key_update) = require_handshake_msg!(m, HandshakeType::KeyUpdate, HandshakePayload::KeyUpdate) {
            self.handle_key_update(sess, key_update)?;
        } else {
            check_message(&m,
                          &[ContentType::ApplicationData, ContentType::Handshake],
                          &[HandshakeType::KeyUpdate])?;
        }

        Ok(self)
    }

    fn export_keying_material(&self,
                              output: &mut [u8],
                              label: &[u8],
                              context: Option<&[u8]>) -> Result<(), TLSError> {
        self.key_schedule.export_keying_material(output, label, context)
    }

    fn perhaps_write_key_update(&mut self, sess: &mut ServerSessionImpl) {
        if self.want_write_key_update {
            self.want_write_key_update = false;
            sess.common.send_msg_encrypt(Message::build_key_update_notify());

            let write_key = self.key_schedule.next_server_application_traffic_secret();
            let scs = sess.common.get_suite_assert();
            sess.common.record_layer.set_message_encrypter(cipher::new_tls13_write(scs, &write_key));
        }
    }
}

#[cfg(feature = "quic")]
pub struct ExpectQUICTraffic {
    key_schedule: KeyScheduleTraffic,
    _fin_verified: verify::FinishedMessageVerified,
}

#[cfg(feature = "quic")]
impl hs::State for ExpectQUICTraffic {
    fn handle(self: Box<Self>, _: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        // reject all messages
        check_message(&m, &[], &[])?;
        unreachable!();
    }

    fn export_keying_material(&self,
                              output: &mut [u8],
                              label: &[u8],
                              context: Option<&[u8]>) -> Result<(), TLSError> {
        self.key_schedule.export_keying_material(output, label, context)
    }
}
