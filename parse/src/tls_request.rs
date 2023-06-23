use crate::tls_cipher_suite::CipherSuite;
use crate::tls_extension::Extension;

// RFC 8446 - TLS 1.3
#[derive(Debug,PartialEq)]
pub struct Record {
    pub r#type: RecordContentType,
    pub legacy_record_version: u16,
    pub length: u16,
    pub fragment: Option<Handshake>,
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
pub enum RecordContentType {
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
pub struct Handshake {
    pub msg_type: HandshakeType,
    pub length: u32,
    pub msg: Option<HandshakeMessage>,
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
pub enum HandshakeType {
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
pub struct HandshakeMessage {
    pub legacy_version: u16,
    pub random: [u8; 0x20],
    pub legacy_session_id: Vec::<u8>,
    pub cipher_suites: Vec::<CipherSuite>,
    pub legacy_compression_methods: Vec::<u8>,
    pub extensions: Vec::<Extension>,
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
        let mut cipher_suites: Vec<CipherSuite> = Vec::new();
        for _ in 0..cipher_suites_length/2 {
            cipher_suites.push(CipherSuite::new(*data.next()?, *data.next()?));
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
                Ok(extension) => extensions.push(extension),
                Err(e) => println!("Unrecognized extension ID: {e:?}"),
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

