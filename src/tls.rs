//! TLS certificate loading and SNI-based certificate selection.
//!
//! A certificate file may contain a single fullchain (leaf followed by its
//! intermediates) or several concatenated fullchains. Private keys may likewise
//! be split across several files or concatenated into one PEM file. Leaves are
//! paired with keys by comparing public keys, and each leaf's chain is rebuilt
//! from the configured certificates by following issuer/subject links.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use rustls::{
    crypto::ring::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::{CertifiedKey, SigningKey},
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

/// One leaf certificate, its issuer chain (leaf first), and matching key.
pub(crate) struct TlsChain {
    pub(crate) cert_chain: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
    pub(crate) signing_key: Arc<dyn SigningKey>,
    names: Vec<String>,
}

/// All configured certificate chains plus the SNI name index used by both the
/// rustls (HTTP/1.1 and HTTP/2) and BoringSSL (HTTP/3) listeners.
pub(crate) struct TlsMaterial {
    chains: Vec<TlsChain>,
    index: SniIndex,
}

impl TlsMaterial {
    pub(crate) fn load(cert_paths: &[PathBuf], key_paths: &[PathBuf]) -> Result<Self> {
        anyhow::ensure!(
            !cert_paths.is_empty(),
            "at least one tls_cert path is required"
        );
        anyhow::ensure!(
            !key_paths.is_empty(),
            "at least one tls_key path is required"
        );

        let mut certs = Vec::new();
        for path in cert_paths {
            read_pem(path, "certificate", |item| {
                if let rustls_pemfile::Item::X509Certificate(cert) = item {
                    certs.push(cert);
                }
            })?;
        }
        let mut seen_certs = HashSet::new();
        certs.retain(|cert| seen_certs.insert(cert.as_ref().to_vec()));
        anyhow::ensure!(
            !certs.is_empty(),
            "no certificates were found in the configured tls_cert file(s)"
        );

        let mut keys = Vec::new();
        for path in key_paths {
            read_pem(path, "private key", |item| match item {
                rustls_pemfile::Item::Pkcs1Key(key) => {
                    keys.push(PrivateKeyDer::Pkcs1(key));
                }
                rustls_pemfile::Item::Pkcs8Key(key) => {
                    keys.push(PrivateKeyDer::Pkcs8(key));
                }
                rustls_pemfile::Item::Sec1Key(key) => {
                    keys.push(PrivateKeyDer::Sec1(key));
                }
                _ => {}
            })?;
        }
        let mut seen_keys = HashSet::new();
        keys.retain(|key| seen_keys.insert(key.secret_der().to_vec()));
        anyhow::ensure!(
            !keys.is_empty(),
            "no private keys were found in the configured tls_key file(s)"
        );

        let parsed_certs = certs
            .iter()
            .map(ParsedCert::parse)
            .collect::<Result<Vec<_>>>()?;

        let mut keys = keys
            .into_iter()
            .map(|key| {
                let signing_key = any_supported_type(&key)
                    .context("TLS private key uses an unsupported algorithm")?;
                Ok((key, signing_key))
            })
            .collect::<Result<Vec<_>>>()?;

        // A single key may be used by several leaf certificates (for example
        // separately issued single-name certificates sharing one key).
        let mut leaves = Vec::new();
        for (cert_index, cert) in certs.iter().enumerate() {
            let matching_key = keys.iter().find(|(_, signing_key)| {
                CertifiedKey::new(vec![cert.clone()], signing_key.clone())
                    .keys_match()
                    .is_ok()
            });
            if let Some((key, signing_key)) = matching_key {
                leaves.push((cert_index, key.clone_key(), signing_key.clone()));
            }
        }
        anyhow::ensure!(
            !leaves.is_empty(),
            "no configured TLS certificate matches any configured private key"
        );

        let matched_keys = leaves
            .iter()
            .map(|(_, key, _)| key.secret_der().to_vec())
            .collect::<HashSet<_>>();
        anyhow::ensure!(
            keys.iter()
                .all(|(key, _)| matched_keys.contains(key.secret_der())),
            "a configured TLS private key does not match any configured certificate"
        );
        keys.clear();

        let mut chains = Vec::with_capacity(leaves.len());
        for (leaf_index, key, signing_key) in leaves {
            chains.push(TlsChain {
                cert_chain: build_chain(leaf_index, &parsed_certs),
                key,
                signing_key,
                names: parsed_certs[leaf_index].names.clone(),
            });
        }

        let mut index = SniIndex::default();
        for (chain_index, chain) in chains.iter().enumerate() {
            for name in &chain.names {
                index.insert(name, chain_index);
            }
        }
        tracing::info!(
            chains = chains.len(),
            names = index.len(),
            "loaded TLS certificate chains for SNI selection"
        );

        Ok(Self { chains, index })
    }

    pub(crate) fn chains(&self) -> &[TlsChain] {
        &self.chains
    }

    pub(crate) fn index(&self) -> &SniIndex {
        &self.index
    }

    pub(crate) fn default_chain_index(&self) -> usize {
        self.index.default
    }
}

fn read_pem(path: &Path, kind: &str, mut on_item: impl FnMut(rustls_pemfile::Item)) -> Result<()> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("cannot open TLS {kind} {}", path.display()))?,
    );
    for item in rustls_pemfile::read_all(&mut reader) {
        let item =
            item.with_context(|| format!("cannot parse TLS {kind} PEM {}", path.display()))?;
        on_item(item);
    }
    Ok(())
}

struct ParsedCert {
    der: CertificateDer<'static>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    names: Vec<String>,
}

impl ParsedCert {
    fn parse(der: &CertificateDer<'static>) -> Result<Self> {
        let (_, certificate) = parse_x509_certificate(der.as_ref())
            .with_context(|| "cannot parse X.509 certificate metadata")?;
        let subject = certificate.subject().as_raw().to_vec();
        let issuer = certificate.issuer().as_raw().to_vec();

        let mut names = Vec::new();
        if let Some(alternative_names) = certificate
            .subject_alternative_name()
            .context("cannot parse certificate subject alternative names")?
        {
            for name in &alternative_names.value.general_names {
                if let GeneralName::DNSName(name) = name {
                    push_name(&mut names, name);
                }
            }
        }
        if names.is_empty() {
            // Compatibility fallback for older certificates that still rely on
            // the common name when no DNS SAN is present.
            for common_name in certificate.subject().iter_common_name() {
                if let Ok(name) = common_name.as_str() {
                    push_name(&mut names, name);
                }
            }
        }

        Ok(Self {
            der: der.clone(),
            subject,
            issuer,
            names,
        })
    }
}

fn push_name(names: &mut Vec<String>, name: &str) {
    if let Some(name) = normalize_dns_name(name) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
}

fn normalize_dns_name(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    let base = name.strip_prefix("*.").unwrap_or(&name);
    if base.is_empty()
        || base.contains('*')
        || base
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || base.split('.').any(str::is_empty)
    {
        return None;
    }
    Some(name)
}

/// Rebuild a leaf-to-root chain by following issuer/subject links. Root
/// certificates present in the input are retained so that a concatenated
/// fullchain round-trips without silently dropping supplied material.
fn build_chain(leaf_index: usize, certs: &[ParsedCert]) -> Vec<CertificateDer<'static>> {
    let mut chain = vec![certs[leaf_index].der.clone()];
    let mut current = leaf_index;
    let mut used = HashSet::from([leaf_index]);

    loop {
        let issuer = &certs[current].issuer;
        if certs[current].subject == *issuer {
            break;
        }
        let Some((next_index, _)) = certs
            .iter()
            .enumerate()
            .find(|(index, cert)| !used.contains(index) && cert.subject == *issuer)
        else {
            break;
        };
        used.insert(next_index);
        chain.push(certs[next_index].der.clone());
        current = next_index;
    }

    chain
}

/// Normalized SNI names mapped to chain indexes. Exact names take precedence
/// over wildcard names, and `default` is used for missing or unknown SNI.
#[derive(Debug, Clone, Default)]
pub(crate) struct SniIndex {
    exact: HashMap<String, usize>,
    wildcard: Vec<(String, usize)>,
    default: usize,
}

impl SniIndex {
    fn insert(&mut self, name: &str, chain_index: usize) {
        if name.starts_with("*.") {
            if !self
                .wildcard
                .iter()
                .any(|(pattern, index)| pattern == name && *index == chain_index)
            {
                self.wildcard.push((name.to_owned(), chain_index));
            }
        } else {
            self.exact.entry(name.to_owned()).or_insert(chain_index);
        }
    }

    fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// Select the chain index for a client-supplied SNI name.
    pub(crate) fn select(&self, server_name: Option<&str>) -> usize {
        let Some(server_name) = server_name else {
            return self.default;
        };
        let Some(name) = normalize_dns_name(server_name) else {
            return self.default;
        };
        if let Some(index) = self.exact.get(&name) {
            return *index;
        }
        self.wildcard
            .iter()
            .find(|(pattern, _)| wildcard_matches(pattern, &name))
            .map_or(self.default, |(_, index)| *index)
    }
}

fn wildcard_matches(pattern: &str, host: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return pattern == host;
    };
    let Some(prefix) = host.strip_suffix(suffix) else {
        return false;
    };
    let Some(label) = prefix.strip_suffix('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

/// rustls certificate resolver using the shared SNI index.
#[derive(Debug)]
pub(crate) struct SniCertResolver {
    index: SniIndex,
    certified: Vec<Arc<CertifiedKey>>,
}

impl SniCertResolver {
    pub(crate) fn new(material: &TlsMaterial) -> Self {
        Self {
            index: material.index.clone(),
            certified: material
                .chains
                .iter()
                .map(|chain| {
                    Arc::new(CertifiedKey::new(
                        chain.cert_chain.clone(),
                        chain.signing_key.clone(),
                    ))
                })
                .collect(),
        }
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let index = self.index.select(client_hello.server_name());
        self.certified
            .get(index)
            .cloned()
            .or_else(|| self.certified.first().cloned())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
    use tempfile::TempDir;

    use super::{wildcard_matches, SniIndex, TlsMaterial};

    struct Fixture {
        _temp: TempDir,
        cert_path: PathBuf,
        key_path: PathBuf,
    }

    fn fixture() -> Fixture {
        let temp = TempDir::new().unwrap();

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "htxpro test CA");
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let example_params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
        let example_key = KeyPair::generate().unwrap();
        let example_cert = example_params
            .signed_by(&example_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();

        let mut test_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        test_params
            .subject_alt_names
            .push(SanType::DnsName("test.com".try_into().unwrap()));
        test_params
            .subject_alt_names
            .push(SanType::DnsName("*.test.com".try_into().unwrap()));
        let test_key = KeyPair::generate().unwrap();
        let test_cert = test_params
            .signed_by(&test_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();

        let cert_path = temp.path().join("fullchain.pem");
        let key_path = temp.path().join("privkey.pem");
        fs::write(
            &cert_path,
            format!(
                "{}{}{}{}",
                example_cert.pem(),
                ca_cert.pem(),
                test_cert.pem(),
                ca_cert.pem()
            ),
        )
        .unwrap();
        fs::write(
            &key_path,
            format!(
                "{}{}",
                example_key.serialize_pem(),
                test_key.serialize_pem()
            ),
        )
        .unwrap();

        Fixture {
            _temp: temp,
            cert_path,
            key_path,
        }
    }

    #[test]
    fn loads_concatenated_multi_domain_fullchains() {
        let fixture = fixture();
        let material = TlsMaterial::load(&[fixture.cert_path], &[fixture.key_path]).unwrap();

        assert_eq!(material.chains().len(), 2);
        // Both chains include the shared CA intermediate.
        assert_eq!(material.chains()[0].cert_chain.len(), 2);
        assert_eq!(material.chains()[1].cert_chain.len(), 2);

        assert_eq!(material.index().select(Some("example.com")), 0);
        assert_eq!(material.index().select(Some("test.com")), 1);
        assert_eq!(material.index().select(Some("WWW.TEST.COM.")), 1);
        // Unknown and missing SNI fall back to the first chain.
        assert_eq!(material.index().select(Some("unknown.test")), 0);
        assert_eq!(material.index().select(None), 0);
    }

    #[test]
    fn supports_separate_certificate_and_key_files() {
        let fixture = fixture();
        let temp = TempDir::new().unwrap();
        let first_cert = temp.path().join("first.pem");
        let second_cert = temp.path().join("second.pem");
        let first_key = temp.path().join("first.key");
        let second_key = temp.path().join("second.key");

        let certs = fs::read_to_string(&fixture.cert_path).unwrap();
        let keys = fs::read_to_string(&fixture.key_path).unwrap();
        let marker = "-----BEGIN CERTIFICATE-----";
        let split = certs.match_indices(marker).nth(2).unwrap().0;
        fs::write(&first_cert, &certs[..split]).unwrap();
        fs::write(&second_cert, &certs[split..]).unwrap();
        let marker = "-----BEGIN PRIVATE KEY-----";
        let split = keys.match_indices(marker).nth(1).unwrap().0;
        fs::write(&first_key, &keys[..split]).unwrap();
        fs::write(&second_key, &keys[split..]).unwrap();

        // Key order intentionally differs from certificate order: pairing must
        // use public-key matching rather than file position.
        let material =
            TlsMaterial::load(&[first_cert, second_cert], &[second_key, first_key]).unwrap();
        assert_eq!(material.chains().len(), 2);
        assert_eq!(material.index().select(Some("example.com")), 0);
        assert_eq!(material.index().select(Some("test.com")), 1);
    }

    #[test]
    fn wildcard_sni_matches_a_single_label() {
        assert!(wildcard_matches("*.example.com", "www.example.com"));
        assert!(!wildcard_matches("*.example.com", "example.com"));
        assert!(!wildcard_matches("*.example.com", "www.eu.example.com"));
        assert!(!wildcard_matches("*.example.com", "badexample.com"));

        let mut index = SniIndex::default();
        index.insert("*.example.com", 1);
        index.insert("api.example.com", 2);
        assert_eq!(index.select(Some("api.example.com")), 2);
        assert_eq!(index.select(Some("www.example.com")), 1);
        assert_eq!(index.select(Some("example.com")), 0);
    }
}
