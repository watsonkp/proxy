mod http_request;

use std::fmt;

use tui::draw;
use tui::Encoding;
use crate::http_request::HTTPRequest;

pub struct Request {
    timestamp: u128,
    data: Vec<u8>,
}

impl Request {
    pub fn new(timestamp: u128, data: Vec<u8>) -> Self {
        Request {
            timestamp: timestamp,
            data: data,
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let hex = self.data.iter()
            .map(|v| format!("{:02X} ", v))
            .take(32)
            .reduce(|mut accum, item| { accum.push_str(&item); accum });
        if let Some(hex) = hex {
            write!(f, "{} bytes {}", self.data.len(), hex)
        } else {
            write!(f, "{} bytes <null>", self.data.len())
        }
    }
}

impl draw::LogEntry for Request {
    fn timestamp(&self) -> String {
        format!("{}", self.timestamp)
    }

    fn to_lines(&self, encoding: &Encoding) -> Vec<String> {
        let body: Vec<String> = match encoding {
            Encoding::Protocol(protocol) => self.parse_protocol(&protocol),
            Encoding::Text => match std::str::from_utf8(&(self.data)) {
                        Ok(s) => s.split("\r\n").map(|s| String::from(s)).collect(),
                        // TODO: Do this without calling collect twice.
                        Err(_) => (self.data.iter().map(|v| format!("{:02X} ", v))
                                    .collect::<Vec<_>>())
                                    .chunks(16)
                                    .map(|v| { v.join(" ") })
                                    .collect(),
                    },
            _ => (self.data.iter().map(|v| format!("{:02X} ", v))
                    .collect::<Vec<_>>())
                    .chunks(16)
                    .map(|v| { v.join(" ") })
                    .collect(),
        };

        let timestamp = self.timestamp();
        let spacer = " ".repeat(timestamp.len());

        let timestamp_column = (0..body.len()).map(|i| { if i == 0 { timestamp.clone() } else { spacer.clone() } });

        let lines: Vec<String> = timestamp_column.zip(body)
                                    .map(|(col1, col2)| { col1.to_owned() + " | " + &col2 })
                                    .collect();

        return lines;
    }

}

impl Request {
    fn parse_protocol(&self, protocol: &str) -> Vec<String> {
        match protocol {
            "http" => {
                if let Some(http) = HTTPRequest::new(&self.data[..]) {
                    let mut lines: Vec<String> = Vec::new();
                    for (key, val) in http.properties().iter() {
                        lines.push(format!("{}: {}", key.to_owned(), val));
                    }
                    return lines;
                } else {
                    return vec![String::from("ERROR: Parsing failed.")];
                }
            },
            _ => {
                vec![String::from("ERROR: Unknown protocol ") + protocol]
            },
        }
    }
}
