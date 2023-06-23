#[derive(Debug,PartialEq)]
pub enum Extension {
    ServerName,
    MaxFragmentLength,
    StatusRequest,
    SupportedGroups,
    ECPointFormats,
    SignatureAlgorithms,
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
                    10 => Ok(Extension::SupportedGroups),
                    // RFC 4492 ECC Cipher Suites
                    11 => Ok(Extension::ECPointFormats),
                    13 => Ok(Extension::SignatureAlgorithms),
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
