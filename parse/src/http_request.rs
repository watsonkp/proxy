// RFC 9112 - HTTP/1.1
#[derive(Debug,PartialEq)]
pub struct HTTPRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HTTPRequest {
    pub fn new(data: &[u8]) -> Option<Self> {
        // Split on \n. Trim optional trailing \r.
        let mut lines = data.split(|&b| b == b'\n');
        // Read request line
        if let Ok(request_line) = std::str::from_utf8(lines.next()?) {
            let mut request_line = request_line.trim().split(' ');
            let (method, target, version) = (request_line.next()?,
                                            request_line.next()?,
                                            request_line.next()?);
            // Read field lines
            let mut headers: Vec<(String, String)> = Vec::new();
            while let Some(header) = lines.next() {
                if header == [b'\r'] || header.len() == 0 {
                    break;
                }
                let mut header = header.splitn(2, |&b| b == b':');
                if let (Ok(name), Ok(value)) = (std::str::from_utf8(header.next()?), std::str::from_utf8(header.next()?)) {
                    headers.push((String::from(name.trim()),
                                    String::from(value.trim())));
                } else {
                    return None;
                }
            }

            // Read message body
            let body = lines.flat_map(|line| line.to_vec())
                            .collect::<Vec<u8>>();

            return Some(HTTPRequest {
                method: String::from(method),
                target: String::from(target),
                version: String::from(version),
                headers: headers,
                body: body,
            });
        }

        return None;
    }

    pub fn properties(&self) -> Vec<(String, String)> {
        let mut properties: Vec<(String, String)> = Vec::<(String, String)>::new();
        properties.push((String::from("method"), self.method.clone()));
        properties.push((String::from("target"), self.target.clone()));
        properties.push((String::from("version"), self.version.clone()));

        for (name, value) in self.headers.iter() {
            properties.push((name.clone(), value.clone()));
        }

        let mut body_length = self.body.len().to_string();
        body_length.push_str(" bytes");
        properties.push((String::from("message body length"), body_length));

        return properties;
    }
}

#[cfg(test)]
mod tests {
    use crate::HTTPRequest;

    #[test]
    fn http_get_request() {
        let request = "GET /AAAA HTTP/1.1\r\nUser-Agent: curl\r\n\r\n";
        let parsed = HTTPRequest::new(request.as_bytes()).unwrap();
        let expected = HTTPRequest {
            method: String::from("GET"),
            target: String::from("/AAAA"),
            version: String::from("HTTP/1.1"),
            headers: vec![(String::from("User-Agent"), String::from("curl"))],
            body: Vec::new(),
        };
        assert_eq!(parsed, expected)
    }

    #[test]
    fn http_post_request() {
        let request = "POST / HTTP/1.1\r\nUser-Agent: curl\r\n\r\nAAAA=BBBB";
        let parsed = HTTPRequest::new(request.as_bytes()).unwrap();
        let expected = HTTPRequest {
            method: String::from("POST"),
            target: String::from("/"),
            version: String::from("HTTP/1.1"),
            headers: vec![(String::from("User-Agent"), String::from("curl"))],
            body: "AAAA=BBBB".as_bytes().to_vec(),
        };
        assert_eq!(parsed, expected)
    }
}
