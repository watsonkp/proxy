// RFC 8446 - TLS 1.3
#[derive(Debug,PartialEq)]
pub struct Record {
    r#type: RecordContentType,
    legacy_record_version: u16,
    length: u16,
    fragment: Option<Handshake>,
}

impl Record {
    pub fn new(data: &[u8]) -> Option<Self> {
        let mut data = data.iter();

        let r#type = RecordContentType::new(data.next()?)?;
        let version: u16 = u16::from_be_bytes([*data.next()?, *data.next()?]);
        let length: u16 = u16::from_be_bytes([*data.next()?, *data.next()?]);

        let handshake = Handshake::new(data);

        return Some(Record {
            r#type: r#type,
            legacy_record_version: version,
            length: length,
            fragment: handshake,
        })
    }

    pub fn properties(&self) -> Vec<(String, String)> {
        let mut properties: Vec<(String, String)> = Vec::<(String, String)>::new();
        properties.push((String::from("record"), format!("length={}", self.length)));
        return properties;
    }
}

#[derive(Debug,PartialEq)]
enum RecordContentType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl RecordContentType {
    fn new(n: &u8) -> Option<Self> {
        match n {
            0 => Some(RecordContentType::Invalid),
            20 => Some(RecordContentType::ChangeCipherSpec),
            21 => Some(RecordContentType::Alert),
            22 => Some(RecordContentType::Handshake),
            23 => Some(RecordContentType::ApplicationData),
            _ => None,
        }
    }
}

#[derive(Debug,PartialEq)]
struct Handshake {
    msg_type: HandshakeType,
    length: u32,
    msg: Option<HandshakeMessage>,
}

impl Handshake {
    fn new(mut data: std::slice::Iter<u8>) -> Option<Self> {
        // Parse handshake protocol
        let msg_type = HandshakeType::new(data.next()?)?;
        let length: u32 = u32::from_be_bytes([0x00, *data.next()?, *data.next()?, *data.next()?]);
        let msg = HandshakeMessage::new(data);

        return Some(Handshake {
            msg_type: msg_type,
            length: length,
            msg: msg,
        })
    }
}

#[derive(Debug,PartialEq)]
enum HandshakeType {
    ClientHello,
    ServerHello,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    KeyUpdate,
    MessageHash,
}

impl HandshakeType {
    fn new(n: &u8) -> Option<Self> {
        match n {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
            5 => Some(HandshakeType::EndOfEarlyData),
            8 => Some(HandshakeType::EncryptedExtensions),
            11 => Some(HandshakeType::Certificate),
            13 => Some(HandshakeType::CertificateRequest),
            15 => Some(HandshakeType::CertificateVerify),
            20 => Some(HandshakeType::Finished),
            24 => Some(HandshakeType::KeyUpdate),
            254 => Some(HandshakeType::MessageHash),
            _ => None,
        }
    }
}

#[derive(Debug,PartialEq)]
struct HandshakeMessage {
    legacy_version: u16,
    random: [u8; 0x20],
    legacy_session_id: Vec::<u8>,
    cipher_suites: Vec::<u8>,
    legacy_compression_methods: Vec::<u8>,
    extensions: Vec::<Extension>,
}

impl HandshakeMessage {
    fn new(mut data: std::slice::Iter<u8>) -> Option<Self> {
        let version: u16 = u16::from_be_bytes([*data.next()?, *data.next()?]);
        let mut random: [u8; 0x20] = [0; 0x20];
        for i in 0..random.len() {
            random[i] = *data.next()?;
        }

        // Parse legacy session ID vector as a u8 length followed by n bytes
        let legacy_session_id_length = data.next()?;
        let mut legacy_session_id = Vec::<u8>::new();
        for _ in 0..*legacy_session_id_length {
            legacy_session_id.push(u8::clone(data.next()?));
        }

        // Parse cipher suites vector as a u16 length followed by n bytes
        let cipher_suites_length: u16 = u16::from_be_bytes([*data.next()?, *data.next()?]);
        let mut cipher_suites = Vec::<u8>::new();
        for _ in 0..cipher_suites_length {
            cipher_suites.push(u8::clone(data.next()?));
        }

        // Parse legacy compression methods vector as a u8 length followed by n bytes
        let legacy_compression_methods_length = *data.next()?;
        let mut legacy_compression_methods = Vec::<u8>::new();
        for _ in 0..legacy_compression_methods_length {
            legacy_compression_methods.push(u8::clone(data.next()?));
        }

        // Parse extensions vector as a u16 length followed by n bytes
        let _extensions_length: u16 = u16::from_be_bytes([*data.next()?, *data.next()?]);
        let mut data = data.peekable();
        let mut extensions = Vec::<Extension>::new();
        while data.peek().is_some() {
            let extension = Extension::new(&mut data);
            match extension {
                Some(extension) => extensions.push(extension),
                None => println!("Received None Result for extension."),
            };
        }

        return Some(HandshakeMessage {
            legacy_version: version,
            random: random,
            legacy_session_id: legacy_session_id,
            cipher_suites: cipher_suites,
            legacy_compression_methods: legacy_compression_methods,
            extensions: extensions,
        });
    }
}

#[derive(Debug,PartialEq)]
struct Extension {
    extension_type: ExtensionType,
    extension_data: Vec<u8>,
}

impl Extension {
    fn new<'a>(data: &mut impl Iterator<Item = &'a u8>) -> Option<Self> {
        let extension_type = ExtensionType::new(u16::from_be_bytes([*data.next()?, *data.next()?]));
        if let Err(e) = extension_type {
            println!("Unrecognized extension ID: {e:?}");
        }

        let extension_data_length: u16 = u16::from_be_bytes([*data.next()?, *data.next()?]);
        let mut extension_data = Vec::<u8>::new();
        for _ in 0..extension_data_length {
            extension_data.push(u8::clone(data.next()?));
        }

        return match extension_type {
            Ok(v) => Some(Extension {
                    extension_type: v,
                    extension_data: extension_data,
                }),
            Err(_) => None,
        }
    }
}

#[derive(Debug,PartialEq)]
enum ExtensionType {
    ServerName,
    MaxFragmentLength,
    StatusRequest,
    SupportedGroups,
    ECPointFormats,
    SignatureAlgorithms,
    UseSRTP,
    Heartbeat,
    ApplicationLayerProtocolNegotiation,
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

impl ExtensionType {
    fn new(n: u16) -> Result<Self, u16> {
        match n {
            0 => Ok(ExtensionType::ServerName),
            1 => Ok(ExtensionType::MaxFragmentLength),
            5 => Ok(ExtensionType::StatusRequest),
            10 => Ok(ExtensionType::SupportedGroups),
            // RFC 4492 ECC Cipher Suites
            11 => Ok(ExtensionType::ECPointFormats),
            13 => Ok(ExtensionType::SignatureAlgorithms),
            14 => Ok(ExtensionType::UseSRTP),
            15 => Ok(ExtensionType::Heartbeat),
            // RFC TLS 7301 Application-Layer Protocol Negotiation
            16 => Ok(ExtensionType::ApplicationLayerProtocolNegotiation),
            18 => Ok(ExtensionType::SignedCertificateTimestamp),
            19 => Ok(ExtensionType::ClientCertificateType),
            20 => Ok(ExtensionType::ServerCertificateType),
            21 => Ok(ExtensionType::Padding),
            // RFC 7366 Encrypt-then-MAC for TLS
            22 => Ok(ExtensionType::EncryptThenMAC),
            // RFC 7627 TLS Session Hash and Extended Master Secret Extension
            23 => Ok(ExtensionType::ExtendedMasterSecret),
            41 => Ok(ExtensionType::PreSharedKey),
            42 => Ok(ExtensionType::EarlyData),
            43 => Ok(ExtensionType::SupportedVersions),
            44 => Ok(ExtensionType::Cookie),
            45 => Ok(ExtensionType::PSKKeyExchangeModes),
            47 => Ok(ExtensionType::CertificateAuthorities),
            48 => Ok(ExtensionType::OIDFilters),
            49 => Ok(ExtensionType::PostHandshakeAuth),
            50 => Ok(ExtensionType::SignatureAlgorithmsCert),
            51 => Ok(ExtensionType::KeyShare),
            _ => Err(n),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tls_request::Record;
    use crate::tls_request::RecordContentType;
    use crate::tls_request::Handshake;
    use crate::tls_request::HandshakeType;
    use crate::tls_request::HandshakeMessage;
    use crate::tls_request::Extension;
    use crate::tls_request::ExtensionType;

    #[test]
    fn tls_hello() {
        let request: [u8; 0x205] = [0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01,
            0xFC, 0x03, 0x03, 0x3C, 0xE1, 0x9E, 0x29, 0xAB,
            0x07, 0x7E, 0x8B, 0xF9, 0xBD, 0x44, 0x98, 0x20,
            0x29, 0x12, 0x71, 0x77, 0x6F, 0x02, 0x09, 0x82,
            0x7C, 0x75, 0xCB, 0x19, 0xE7, 0x64, 0x96, 0xB5,
            0x72, 0xC6, 0x2B, 0x20, 0xB0, 0x1B, 0x52, 0xC7,
            0x41, 0xE1, 0xF4, 0x89, 0x2E, 0x64, 0x37, 0x06,
            0x5E, 0x70, 0x62, 0x1C, 0xBC, 0xC5, 0x88, 0xC8,
            0x90, 0xA7, 0xEC, 0xA8, 0x92, 0xAD, 0x7F, 0x22,
            0x82, 0xB9, 0x35, 0xD9, 0x00, 0xB6, 0x13, 0x02,
            0x13, 0x03, 0x13, 0x01, 0xC0, 0x2C, 0xC0, 0x30,
            0x00, 0xA3, 0x00, 0x9F, 0xCC, 0xA9, 0xCC, 0xA8,
            0xCC, 0xAA, 0xC0, 0xAF, 0xC0, 0xAD, 0xC0, 0xA3,
            0xC0, 0x9F, 0xC0, 0x5D, 0xC0, 0x61, 0xC0, 0x57,
            0xC0, 0x53, 0x00, 0xA7, 0xC0, 0x2B, 0xC0, 0x2F,
            0x00, 0xA2, 0x00, 0x9E, 0xC0, 0xAE, 0xC0, 0xAC,
            0xC0, 0xA2, 0xC0, 0x9E, 0xC0, 0x5C, 0xC0, 0x60,
            0xC0, 0x56, 0xC0, 0x52, 0x00, 0xA6, 0xC0, 0x24,
            0xC0, 0x28, 0x00, 0x6B, 0x00, 0x6A, 0xC0, 0x73,
            0xC0, 0x77, 0x00, 0xC4, 0x00, 0xC3, 0x00, 0x6D,
            0x00, 0xC5, 0xC0, 0x23, 0xC0, 0x27, 0x00, 0x67,
            0x00, 0x40, 0xC0, 0x72, 0xC0, 0x76, 0x00, 0xBE,
            0x00, 0xBD, 0x00, 0x6C, 0x00, 0xBF, 0xC0, 0x0A,
            0xC0, 0x14, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88,
            0x00, 0x87, 0xC0, 0x19, 0x00, 0x3A, 0x00, 0x89,
            0xC0, 0x09, 0xC0, 0x13, 0x00, 0x33, 0x00, 0x32,
            0x00, 0x9A, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44,
            0xC0, 0x18, 0x00, 0x34, 0x00, 0x9B, 0x00, 0x46,
            0x00, 0x9D, 0xC0, 0xA1, 0xC0, 0x9D, 0xC0, 0x51,
            0x00, 0x9C, 0xC0, 0xA0, 0xC0, 0x9C, 0xC0, 0x50,
            0x00, 0x3D, 0x00, 0xC0, 0x00, 0x3C, 0x00, 0xBA,
            0x00, 0x35, 0x00, 0x84, 0x00, 0x2F, 0x00, 0x96,
            0x00, 0x41, 0x00, 0xFF, 0x01, 0x00, 0x00, 0xFD,
            0x00, 0x0B, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
            0x00, 0x0A, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1D,
            0x00, 0x17, 0x00, 0x1E, 0x00, 0x19, 0x00, 0x18,
            0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
            0x01, 0x04, 0x00, 0x10, 0x00, 0x0E, 0x00, 0x0C,
            0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70,
            0x2F, 0x31, 0x2E, 0x31, 0x00, 0x16, 0x00, 0x00,
            0x00, 0x17, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00,
            0x00, 0x0D, 0x00, 0x30, 0x00, 0x2E, 0x04, 0x03,
            0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
            0x08, 0x09, 0x08, 0x0A, 0x08, 0x0B, 0x08, 0x04,
            0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
            0x06, 0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01,
            0x02, 0x01, 0x03, 0x02, 0x02, 0x02, 0x04, 0x02,
            0x05, 0x02, 0x06, 0x02, 0x00, 0x2B, 0x00, 0x09,
            0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03,
            0x01, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x01, 0x00,
            0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1D, 0x00,
            0x20, 0x3F, 0xD6, 0x40, 0xC8, 0x78, 0x04, 0x9D,
            0x3B, 0xBA, 0x37, 0x19, 0xE2, 0xCE, 0xB4, 0x5B,
            0xA2, 0x45, 0x70, 0x2C, 0xE5, 0xE8, 0xE3, 0x3E,
            0x12, 0x27, 0xAC, 0xA5, 0x75, 0xB9, 0xAB, 0xB1,
            0x16, 0x00, 0x15, 0x00, 0x48, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00];
        let parsed = Record::new(&request).unwrap();
        let expected = Record {
            r#type: RecordContentType::Handshake,
            legacy_record_version: 0x0301,
            length: 0x0200,
            fragment: Some(Handshake {
                msg_type: HandshakeType::ClientHello,
                length: 0x1FC,
                msg: Some(HandshakeMessage {
                    legacy_version: 0x0303,
                    random: [
                        0x3C, 0xE1, 0x9E, 0x29, 0xAB, 0x07, 0x7E, 0x8B,
                        0xF9, 0xBD, 0x44, 0x98, 0x20, 0x29, 0x12, 0x71,
                        0x77, 0x6F, 0x02, 0x09, 0x82, 0x7C, 0x75, 0xCB,
                        0x19, 0xE7, 0x64, 0x96, 0xB5, 0x72, 0xC6, 0x2B],
                    legacy_session_id: vec![
                        0xB0, 0x1B, 0x52, 0xC7, 0x41, 0xE1, 0xF4, 0x89,
                        0x2E, 0x64, 0x37, 0x06, 0x5E, 0x70, 0x62, 0x1C,
                        0xBC, 0xC5, 0x88, 0xC8, 0x90, 0xA7, 0xEC, 0xA8,
                        0x92, 0xAD, 0x7F, 0x22, 0x82, 0xB9, 0x35, 0xD9],
                    cipher_suites: vec![
                        0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xC0, 0x2C,
                        0xC0, 0x30, 0x00, 0xA3, 0x00, 0x9F, 0xCC, 0xA9,
                        0xCC, 0xA8, 0xCC, 0xAA, 0xC0, 0xAF, 0xC0, 0xAD,
                        0xC0, 0xA3, 0xC0, 0x9F, 0xC0, 0x5D, 0xC0, 0x61,
                        0xC0, 0x57, 0xC0, 0x53, 0x00, 0xA7, 0xC0, 0x2B,
                        0xC0, 0x2F, 0x00, 0xA2, 0x00, 0x9E, 0xC0, 0xAE,
                        0xC0, 0xAC, 0xC0, 0xA2, 0xC0, 0x9E, 0xC0, 0x5C,
                        0xC0, 0x60, 0xC0, 0x56, 0xC0, 0x52, 0x00, 0xA6,
                        0xC0, 0x24, 0xC0, 0x28, 0x00, 0x6B, 0x00, 0x6A,
                        0xC0, 0x73, 0xC0, 0x77, 0x00, 0xC4, 0x00, 0xC3,
                        0x00, 0x6D, 0x00, 0xC5, 0xC0, 0x23, 0xC0, 0x27,
                        0x00, 0x67, 0x00, 0x40, 0xC0, 0x72, 0xC0, 0x76,
                        0x00, 0xBE, 0x00, 0xBD, 0x00, 0x6C, 0x00, 0xBF,
                        0xC0, 0x0A, 0xC0, 0x14, 0x00, 0x39, 0x00, 0x38,
                        0x00, 0x88, 0x00, 0x87, 0xC0, 0x19, 0x00, 0x3A,
                        0x00, 0x89, 0xC0, 0x09, 0xC0, 0x13, 0x00, 0x33,
                        0x00, 0x32, 0x00, 0x9A, 0x00, 0x99, 0x00, 0x45,
                        0x00, 0x44, 0xC0, 0x18, 0x00, 0x34, 0x00, 0x9B,
                        0x00, 0x46, 0x00, 0x9D, 0xC0, 0xA1, 0xC0, 0x9D,
                        0xC0, 0x51, 0x00, 0x9C, 0xC0, 0xA0, 0xC0, 0x9C,
                        0xC0, 0x50, 0x00, 0x3D, 0x00, 0xC0, 0x00, 0x3C,
                        0x00, 0xBA, 0x00, 0x35, 0x00, 0x84, 0x00, 0x2F,
                        0x00, 0x96, 0x00, 0x41, 0x00, 0xFF],
                    legacy_compression_methods: vec![0x00],
                    extensions: vec![Extension {
                        extension_type: ExtensionType::Cookie,
                        extension_data: vec![]}],
                }),
            }),
        };
        assert_eq!(parsed, expected)
    }
}
