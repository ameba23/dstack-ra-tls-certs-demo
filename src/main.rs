use anyhow::Result;
use ra_tls::attestation::{Attestation, QuoteContentType, VersionedAttestation};
use ra_tls::cert::CertRequest;
use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Use dstack-attest
fn attestation_using_dstack_attest(input: Vec<u8>) -> Result<VersionedAttestation> {
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&input);
    Ok(Attestation::quote(&report_data)?.into_versioned())
}

/// Demostrate that it is possible to use some custom payload for eg: Azure vTPM
fn some_custom_attestation_payload(input: Vec<u8>) -> Result<VersionedAttestation> {
    Ok(VersionedAttestation::V0 {
        attestation: Attestation {
            quote: ra_tls::attestation::AttestationQuote::DstackTdx(
                ra_tls::attestation::TdxQuote {
                    quote: b"some custom data".to_vec(),
                    event_log: Vec::new(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: to_fixed_64(input),
            config: String::new(),
            report: (),
        },
    })
}

/// Create a self-signed certificate with attestation given in a certificate extension
fn self_signed_ra_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();

    // let attestation = attestation_using_dstack_attest(pubkey)?;
    let attestation = some_custom_attestation_payload(pubkey)?;

    let cert = CertRequest::builder()
        .key(&key)
        .subject("self-signed-ra")
        .usage_server_auth(true)
        .usage_client_auth(false)
        .attestation(&attestation)
        .build()
        .self_signed()?;

    let key_der: PrivateKeyDer<'static> = key
        .serialize_der()
        .try_into()
        .map_err(|e: &'static str| anyhow::anyhow!(e))?;
    Ok((cert.der().to_vec().into(), key_der))
}

/// Truncate / pad pubkey to 64 bytes (in production we would probaby hash it)
fn to_fixed_64(v: Vec<u8>) -> [u8; 64] {
    let mut out = [0u8; 64];
    let n = v.len().min(64);
    out[..n].copy_from_slice(&v[..n]);
    out
}

fn main() -> Result<()> {
    if tokio_rustls::rustls::crypto::CryptoProvider::get_default().is_none() {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| anyhow::anyhow!("failed to install rustls aws-lc-rs provider"))?;
    }

    let (cert, key) = self_signed_ra_cert()?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    println!("ServerConfig: {server_config:?}");
    Ok(())
}
