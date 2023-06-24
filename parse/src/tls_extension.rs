#[derive(Debug,PartialEq)]
pub enum Extension {
    ServerName,
    MaxFragmentLength,
    StatusRequest,
    SupportedGroups(Vec<NamedGroup>),
    ECPointFormats,
    SignatureAlgorithms(Vec<SignatureScheme>),
    UseSRTP,
    Heartbeat,
    ApplicationLayerProtocolNegotiation(ALPN),
    SignedCertificateTimestamp,
    ClientCertificateType,
    ServerCertificateType,
    Padding,
    EncryptThenMAC,
    ExtendedMasterSecret,
    PreSharedKey,
    EarlyData,
    SupportedVersions,
    Cookie,
    PSKKeyExchangeModes,
    CertificateAuthorities,
    OIDFilters,
    PostHandshakeAuth,
    SignatureAlgorithmsCert,
    KeyShare,
}

impl Extension {
    pub fn new<'a>(data: &mut impl Iterator<Item = &'a u8>) -> Result<Self, u16> {
        if let (Some(b0), Some(b1)) = (data.next(), data.next()) {
            let extension_type = u16::from_be_bytes([*b0, *b1]);
            if let (Some(b0), Some(b1)) = (data.next(), data.next()) {
                let extension_data_length: u16 = u16::from_be_bytes([*b0, *b1]);
                let mut extension_data = Vec::<u8>::new();
                for _ in 0..extension_data_length {
                    if let Some(b) = data.next() {
                        extension_data.push(u8::clone(b));
                    } else {
                        return Err(0);
                    }
                }
                return match extension_type {
                    0 => Ok(Extension::ServerName),
                    1 => Ok(Extension::MaxFragmentLength),
                    5 => Ok(Extension::StatusRequest),
                    10 => Ok(Extension::SupportedGroups(Self::parse_named_groups(extension_data))),
                    // RFC 4492 ECC Cipher Suites
                    11 => Ok(Extension::ECPointFormats),
                    13 => Ok(Extension::SignatureAlgorithms(Self::parse_signature_schemes(extension_data))),
                    14 => Ok(Extension::UseSRTP),
                    15 => Ok(Extension::Heartbeat),
                    // RFC TLS 7301 Application-Layer Protocol Negotiation
                    16 => Ok(Extension::ApplicationLayerProtocolNegotiation(ALPN::new(extension_data))),
                    18 => Ok(Extension::SignedCertificateTimestamp),
                    19 => Ok(Extension::ClientCertificateType),
                    20 => Ok(Extension::ServerCertificateType),
                    21 => Ok(Extension::Padding),
                    // RFC 7366 Encrypt-then-MAC for TLS
                    22 => Ok(Extension::EncryptThenMAC),
                    // RFC 7627 TLS Session Hash and Extended Master Secret Extension
                    23 => Ok(Extension::ExtendedMasterSecret),
                    41 => Ok(Extension::PreSharedKey),
                    42 => Ok(Extension::EarlyData),
                    43 => Ok(Extension::SupportedVersions),
                    44 => Ok(Extension::Cookie),
                    45 => Ok(Extension::PSKKeyExchangeModes),
                    47 => Ok(Extension::CertificateAuthorities),
                    48 => Ok(Extension::OIDFilters),
                    49 => Ok(Extension::PostHandshakeAuth),
                    50 => Ok(Extension::SignatureAlgorithmsCert),
                    51 => Ok(Extension::KeyShare),
                    _ => Err(extension_type),
                };
            }
        }
        return Err(0);
    }

    fn parse_signature_schemes(data: Vec<u8>) -> Vec<SignatureScheme> {
        let mut i = 0;
        let mut supported_signature_algorithms: Vec<SignatureScheme> = Vec::new();
        let data_length: u16 = u16::from_be_bytes([data[0], data[1]]);
        i = i + 2;
        let data_length = usize::from(data_length);
        while i < data_length {
            let id: u16 = u16::from_be_bytes([data[i], data[i + 1]]);
            i = i + 2;
            supported_signature_algorithms.push(SignatureScheme::new(id));
        }
        return supported_signature_algorithms;
    }

    fn parse_named_groups(data: Vec<u8>) -> Vec<NamedGroup> {
        let mut i = 0;
        let mut named_group_list: Vec<NamedGroup> = Vec::new();
        let data_length: u16 = u16::from_be_bytes([data[0], data[1]]);
        i = i + 2;
        let data_length = usize::from(data_length);
        while i < data_length {
            let id: u16 = u16::from_be_bytes([data[i], data[i + 1]]);
            i = i + 2;
            named_group_list.push(NamedGroup::new(id));
        }
        return named_group_list;
    }
}

#[derive(Debug,PartialEq)]
pub struct ALPN {
    pub protocol_name_list: Vec<String>,
}

impl ALPN {
    fn new(data: Vec<u8>) -> Self {
        let mut i = 0;
        let mut protocol_name_list: Vec<String> = Vec::new();
        let data_length: u16 = u16::from_be_bytes([data[0], data[1]]);
        i = i + 2;
        let data_length = usize::from(data_length);
        while i < data_length {
            let length = usize::from(data[i]);
            i = i + 1;
            match std::str::from_utf8(&data[i..i+length]) {
                Ok(protocol_name) => protocol_name_list.push(protocol_name.to_string()),
                Err(e) => println!("{e:?}"),
            }
            i = i + length;
        }
        return ALPN {
            protocol_name_list: protocol_name_list,
        }
    }
}

#[derive(Debug,PartialEq)]
pub enum SignatureScheme {
    // RFC 5246 TLS 1.2
    SHA1DSA,
    SHA224RSA,
    SHA224DSA,
    SHA224ECDSA,
    SHA256RSA,
    SHA256DSA,
    SHA256ECDSA,
    SHA384RSA,
    SHA384DSA,
    SHA384ECDSA,
    SHA512RSA,
    SHA512DSA,
    SHA512ECDSA,
    // RFC 8446 TLS 1.3
    RSAPKCS1SHA256,
    RSAPKCS1SHA384,
    RSAPKCS1SHA512,
    ECDSASECP256R1SHA256,
    ECDSASECP384R1SHA384,
    ECDSASECP521R1SHA512,
    RSAPSSRSAESHA256,
    RSAPSSRSAESHA384,
    RSAPSSRSAESHA512,
    ED25519,
    ED448,
    RSAPSSPSSSHA256,
    RSAPSSPSSSHA384,
    RSAPSSPSSSHA512,
    RSAPKCS1SHA1,
    ECDSASHA1,
    PrivateUse,
    Missing(u16),
}

impl SignatureScheme {
    fn new(n: u16) -> Self {
        match n {
            // RFC 5246 TLS 1.2
            0x0202 => SignatureScheme::SHA1DSA,
            0x0301 => SignatureScheme::SHA224RSA,
            0x0302 => SignatureScheme::SHA224DSA,
            0x0303 => SignatureScheme::SHA224ECDSA,
            0x0402 => SignatureScheme::SHA256DSA,
            0x0502 => SignatureScheme::SHA384DSA,
            0x0602 => SignatureScheme::SHA512DSA,
            // RFC 8446 TLS 1.3
            0x0401 => SignatureScheme::RSAPKCS1SHA256,
            0x0501 => SignatureScheme::RSAPKCS1SHA384,
            0x0601 => SignatureScheme::RSAPKCS1SHA512,
            0x0403 => SignatureScheme::ECDSASECP256R1SHA256,
            0x0503 => SignatureScheme::ECDSASECP384R1SHA384,
            0x0603 => SignatureScheme::ECDSASECP521R1SHA512,
            0x0804 => SignatureScheme::RSAPSSRSAESHA256,
            0x0805 => SignatureScheme::RSAPSSRSAESHA384,
            0x0806 => SignatureScheme::RSAPSSRSAESHA512,
            0x0807 => SignatureScheme::ED25519,
            0x0808 => SignatureScheme::ED448,
            0x0809 => SignatureScheme::RSAPSSPSSSHA256,
            0x080A => SignatureScheme::RSAPSSPSSSHA384,
            0x080B => SignatureScheme::RSAPSSPSSSHA512,
            0x0201 => SignatureScheme::RSAPKCS1SHA1,
            0x0203 => SignatureScheme::ECDSASHA1,
            0xFE00..=0xFFFF => SignatureScheme::PrivateUse,
            _ => SignatureScheme::Missing(n),
        }
    }
}

#[derive(Debug,PartialEq)]
pub enum NamedGroup {
    // RFC 8446 TLS 1.3
    SECP256R1,
    SECP384R1,
    SECP521R1,
    X25519,
    X448,
    FFDHE2048,
    FFDHE3072,
    FFDHE4096,
    FFDHE6144,
    FFDHE8192,
    FFDHEPrivateUse,
    ECDHEPrivateUse,
    Missing(u16),
}

impl NamedGroup {
    fn new(n: u16) -> Self {
        match n {
            // RFC 8446 TLS 1.3
            0x0017 => NamedGroup::SECP256R1,
            0x0018 => NamedGroup::SECP384R1,
            0x0019 => NamedGroup::SECP521R1,
            0x001D => NamedGroup::X25519,
            0x001E => NamedGroup::X448,
            0x0100 => NamedGroup::FFDHE2048,
            0x0101 => NamedGroup::FFDHE3072,
            0x0102 => NamedGroup::FFDHE4096,
            0x0103 => NamedGroup::FFDHE6144,
            0x0104 => NamedGroup::FFDHE8192,
            0x01FC..=0x01FF => NamedGroup::FFDHEPrivateUse,
            0xFE00..=0xFEFF => NamedGroup::ECDHEPrivateUse,
            _ => NamedGroup::Missing(n),
        }
    }
}
