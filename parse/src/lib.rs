use std::fmt;

use tui::draw;

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
}
