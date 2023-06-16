use std::time::SystemTime;
use std::io::{Read, Write};
use std::io::BufReader;
use std::net::TcpListener;
use std::thread;
use std::sync::mpsc;

use parse;

pub fn start(address: &'static str, sender: mpsc::Sender<parse::Request>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind(address).unwrap();
        loop {
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(n) => n.as_millis(),
                        Err(_) => 0,
                    };
                    // An HTTP request will keep the connection open while waiting for a response.
                    let mut buf_reader = BufReader::new(&stream);
                    let mut body = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        match buf_reader.read(&mut buf) {
                            Ok(n) => {
                                body.extend_from_slice(&buf[..n]);
                                if n <= 1024 {
                                    break;
                                }
                            },
                            Err(_) => { },
                        };
                    }
                    match sender.send(parse::Request::new(timestamp, body)) {
                        Ok(_) => {},
                        Err(_) => {},
                    };
                    stream.write_all("HTTP/1.1 200 OK\r\n\r\n".as_bytes()).unwrap();
                },
                Err(_) => { },
            };
        }
    })
}
