use std::fmt;

use tui::draw;

pub struct Request {
    timestamp: u128,
    data: Vec<u8>,
}

impl Request {
    pub fn new(timestamp: u128, data: Vec<u8>) -> Self {
        // TODO: Conditional parsing of different protocols.
        // TODO: Fix requests being 1024 bytes with many trailing zeros.
        let http_end = vec![0xd, 0xa, 0xd, 0xa];
        let i = (0..(data.len() - http_end.len()))
            .filter(|&i| { data[i..(i + http_end.len())] == http_end })
            .next();
        let length = match i {
            None => data.len(),
            Some(end) => end + http_end.len(),
        };
        Request {
            timestamp: timestamp,
            data: data[..length].to_vec(),
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        //write!(f, "{}", self.data.len());
        let hex = self.data.iter()
            .map(|v| format!("{:02X} ", v))
            .take(32)
            .reduce(|mut accum, item| { accum.push_str(&item); accum });
        if let Some(hex) = hex {
            write!(f, "{} bytes {}", self.data.len(), hex)
        } else {
            write!(f, "{} bytes <null>", self.data.len())
        }
        //match write!(f, "{}", self.data.iter().map(|v| format!("{:02X} ", v))
        //    .take(32)
        //    .reduce(|mut accum, item| { accum.push_str(&item); accum }) {
        //    Some(_) => Ok(),
        //    None => Ok(),
        //};
        //Ok(())
    }
}

impl draw::LogEntry for Request {
    fn timestamp(&self) -> String {
        format!("{}", self.timestamp)
    }

    fn to_lines(&self) -> Vec<String> {
        let hex: Vec<String> = self.data.iter()
            .map(|v| format!("{:02X} ", v)).collect();

        let timestamp = self.timestamp();
        let spacer = " ".repeat(timestamp.len());

        let body = hex.chunks(16).map(|v| { v.join(" ") });
        let timestamp_column = (0..body.len()).map(|i| { if i == 0 { timestamp.clone() } else { spacer.clone() } });

        let lines: Vec<String> = timestamp_column.zip(body).map(|(col1, col2)| { col1.to_owned() + " | " + &col2 }).collect();

        return lines;
    }
}
