mod tests {
    use parse::tls_request::{Record, RecordContentType, Handshake, HandshakeType, HandshakeMessage};
    use parse::tls_cipher_suite::CipherSuite;
    use parse::tls_extension::{Extension, ALPN, SignatureScheme};

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
                        CipherSuite::TLSAES256GCMSHA384,
                        CipherSuite::TLSChaCha20Poly1305SHA256,
                        CipherSuite::TLSAES128GCMSHA256,
                        CipherSuite::TLSECDHEECDSAWithAES256GCMSHA384,
                        CipherSuite::TLSECDHERSAWithAES256GCMSHA384,
                        CipherSuite::TLSDHEDSSWithAES256GCMSHA384,
                        CipherSuite::TLSDHERSAWithAES256GCMSHA384,
                        CipherSuite::TLSECDHEECDSAWithChaCha20Poly1305SHA256,
                        CipherSuite::TLSECDHERSAWithChaCha20Poly1305SHA256,
                        CipherSuite::TLSDHERSAWithChaCha20Poly1305SHA256,
                        CipherSuite::TLSECDHEECDSAWithAES256CCM8,
                        CipherSuite::TLSECDHEECDSAWithAES256CCM,
                        CipherSuite::TLSDHERSAWithAES256CCM8,
                        CipherSuite::TLSDHERSAWithAES256CCM,
                        CipherSuite::TLSECDHEECDSAWithARIA256GCMSHA384,
                        CipherSuite::TLSECDHERSAWithARIA256GCMSHA384,
                        CipherSuite::TLSDHEDSSWithARIA256GCMSHA384,
                        CipherSuite::TLSDHERSAWithARIA256GCMSHA384,
                        CipherSuite::TLSDHanonWithAES256GCMSHA384,
                        CipherSuite::TLSECDHEECDSAWithAES128GCMSHA256,
                        CipherSuite::TLSECDHERSAWithAES128GCMSHA256,
                        CipherSuite::TLSDHEDSSWithAES128GCMSHA256,
                        CipherSuite::TLSDHERSAWithAES128GCMSHA256,
                        CipherSuite::TLSECDHEECDSAWithAES128CCM8,
                        CipherSuite::TLSECDHEECDSAWithAES128CCM,
                        CipherSuite::TLSDHERSAWithAES128CCM8,
                        CipherSuite::TLSDHERSAWithAES128CCM,
                        CipherSuite::TLSECDHEECDSAWithARIA128GCMSHA256,
                        CipherSuite::TLSECDHERSAWithARIA128GCMSHA256,
                        CipherSuite::TLSDHEDSSWithARIA128GCMSHA256,
                        CipherSuite::TLSDHERSAWithARIA128GCMSHA256,
                        CipherSuite::TLSDHanonWithAES128GCMSHA256,
                        CipherSuite::TLSECDHEECDSAWithAES256CBCSHA384,
                        CipherSuite::TLSECDHERSAWithAES256CBCSHA384,
                        CipherSuite::TLSDHERSAWithAES256CBCSHA256,
                        CipherSuite::TLSDHEDSSWithAES256CBCSHA256,
                        CipherSuite::TLSECDHEECDSAWithCamellia256CBCSHA384,
                        CipherSuite::TLSECDHERSAWithCamellia256CBCSHA384,
                        CipherSuite::TLSDHERSAWithCamellia256CBCSHA256,
                        CipherSuite::TLSDHEDSSWithCamellia256CBCSHA256,
                        CipherSuite::TLSDHAnonWithAES256CBCSHA256,
                        CipherSuite::TLSDHanonWithCamellia256CBCSHA256,
                        CipherSuite::TLSECDHEECDSAWithAES128CBCSHA256,
                        CipherSuite::TLSECDHERSAWithAES128CBCSHA256,
                        CipherSuite::TLSDHERSAWithAES128CBCSHA256,
                        CipherSuite::TLSDHEDSSWithAES128CBCSHA256,
                        CipherSuite::TLSECDHEECDSAWithCamellia128CBCSHA256,
                        CipherSuite::TLSECDHERSAWithCamellia128CBCSHA256,
                        CipherSuite::TLSDHERSAWithCamellia128CBCSHA256,
                        CipherSuite::TLSDHEDSSWithCamellia128CBCSHA256,
                        CipherSuite::TLSDHAnonWithAES128CBCSHA256,
                        CipherSuite::TLSDHanonWithCamellia128CBCSHA256,
                        CipherSuite::TLSECDHEECDSAWithAES256CBCSHA,
                        CipherSuite::TLSECDHERSAWithAES256CBCSHA,
                        CipherSuite::TLSDHERSAWithAES256CBCSHA,
                        CipherSuite::TLSDHEDSSWithAES256CBCSHA,
                        CipherSuite::TLSDHERSAWithCamellia256CBCSHA,
                        CipherSuite::TLSDHEDSSWithCamellia256CBCSHA,
                        CipherSuite::TLSECDHAnonWithAES256CBCSHA,
                        CipherSuite::TLSDHAnonWithAES256CBCSHA,
                        CipherSuite::TLSDHanonWithCamellia256CBCSHA,
                        CipherSuite::TLSECDHEECDSAWithAES128CBCSHA,
                        CipherSuite::TLSECDHERSAWithAES128CBCSHA,
                        CipherSuite::TLSDHERSAWithAES128CBCSHA,
                        CipherSuite::TLSDHEDSSWithAES128CBCSHA,
                        CipherSuite::TLSDHERSAWithSEEDCBCSHA,
                        CipherSuite::TLSDHEDSSWithSEEDCBCSHA,
                        CipherSuite::TLSDHERSAWithCamellia128CBCSHA,
                        CipherSuite::TLSDHEDSSWithCamellia128CBCSHA,
                        CipherSuite::TLSECDHAnonWithAES128CBCSHA,
                        CipherSuite::TLSDHAnonWithAES128CBCSHA,
                        CipherSuite::TLSDHAnonWithSEEDCBCSHA,
                        CipherSuite::TLSDHanonWithCamellia128CBCSHA,
                        CipherSuite::TLSRSAWithAES256GCMSHA384,
                        CipherSuite::TLSRSAWithAES256CCM8,
                        CipherSuite::TLSRSAWithAES256CCM,
                        CipherSuite::TLSRSAWithARIA256GCMSHA384,
                        CipherSuite::TLSRSAWithAES128GCMSHA256,
                        CipherSuite::TLSRSAWithAES128CCM8,
                        CipherSuite::TLSRSAWithAES128CCM,
                        CipherSuite::TLSRSAWithARIA128GCMSHA256,
                        CipherSuite::TLSRSAWithAES256CBCSHA256,
                        CipherSuite::TLSRSAWithCamellia256CBCSHA256,
                        CipherSuite::TLSRSAWithAES128CBCSHA256,
                        CipherSuite::TLSRSAWithCamellia128CBCSHA256,
                        CipherSuite::TLSRSAWithAES256CBCSHA,
                        CipherSuite::TLSRSAWithCamellia256CBCSHA,
                        CipherSuite::TLSRSAWithAES128CBCSHA,
                        CipherSuite::TLSRSAWithSEEDCBCSHA,
                        CipherSuite::TLSRSAWithCamellia128CBCSHA,
                        CipherSuite::TLSEmptyRenegotiationInfoSCSV,
                    ],
                    legacy_compression_methods: vec![0x00],
                    extensions: vec![Extension::ECPointFormats,
                                    Extension::SupportedGroups,
                                    Extension::ApplicationLayerProtocolNegotiation(ALPN { protocol_name_list: vec!["h2".to_string(), "http/1.1".to_string()] }),
                                    Extension::EncryptThenMAC,
                                    Extension::ExtendedMasterSecret,
                                    Extension::PostHandshakeAuth,
                                    Extension::SignatureAlgorithms(vec![
                                        SignatureScheme::ECDSASECP256R1SHA256,
                                        SignatureScheme::ECDSASECP384R1SHA384,
                                        SignatureScheme::ECDSASECP521R1SHA512,
                                        SignatureScheme::ED25519,
                                        SignatureScheme::ED448,
                                        SignatureScheme::RSAPSSPSSSHA256,
                                        SignatureScheme::RSAPSSPSSSHA384,
                                        SignatureScheme::RSAPSSPSSSHA512,
                                        SignatureScheme::RSAPSSRSAESHA256,
                                        SignatureScheme::RSAPSSRSAESHA384,
                                        SignatureScheme::RSAPSSRSAESHA512,
                                        SignatureScheme::RSAPKCS1SHA256,
                                        SignatureScheme::RSAPKCS1SHA384,
                                        SignatureScheme::RSAPKCS1SHA512,
                                        SignatureScheme::SHA224ECDSA,
                                        SignatureScheme::ECDSASHA1,
                                        SignatureScheme::SHA224RSA,
                                        SignatureScheme::RSAPKCS1SHA1,
                                        SignatureScheme::SHA224DSA,
                                        SignatureScheme::SHA1DSA,
                                        SignatureScheme::SHA256DSA,
                                        SignatureScheme::SHA384DSA
                                    ]),
                                    Extension::SupportedVersions,
                                    Extension::PSKKeyExchangeModes,
                                    Extension::KeyShare,
                                    Extension::Padding],
                }),
            }),
        };
        assert_eq!(parsed, expected)
    }
}
