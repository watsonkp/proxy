use std::io;
use std::thread;
use std::io::Read;
use std::sync::mpsc;

use tui::UI;
use tui::Encoding;
use tui::draw;
use tui::draw::Colour::TrueColour;
use parse;
use proxy;

fn read_commands(sender: mpsc::Sender<char>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 1];
        loop {
            match io::stdin().read(&mut buf) {
                Ok(_) => {
                    match sender.send(char::from(buf[0])) {
                        Ok(_) => {},
                        Err(_) => {},
                    };
                },
                Err(_) => { },
            };
        }
    })
}

fn main() {
    let render = |rows, cols, model: &Vec<parse::Request>, encoding: &Encoding| {
        draw::fill((1,1), rows, cols, Some(TrueColour { red: 0xcb, green: 0xc9, blue: 0xe2 }));
        draw::log((1,1), model, encoding);
        draw::status_line(rows, cols);
    };

    let mut ui = UI::new(Vec::new(), render);
    ui.start();

    let (proxy_tx, proxy_rx) = mpsc::channel();
    proxy::start("127.0.0.1:7878", proxy_tx);

    let (key_tx, key_rx) = mpsc::channel();
    read_commands(key_tx);

    let mut with_option = false;
    let mut option = String::from("");
    loop {
        match proxy_rx.try_recv() {
            Ok(received) => ui.add_data(received),
            Err(_) => {},
        };

        if let Ok(key) = key_rx.try_recv() {
            if key != '\n' && with_option {
                option.push(key);
            } else {
                match key {
                    'q' => break,
                    't' => ui.set_encoding(Encoding::Text),
                    'x' => ui.set_encoding(Encoding::Hex),
                    'p' => with_option = true,
                    '\n' => { ui.set_encoding(Encoding::Protocol(option)); with_option = false; option = String::from(""); },
                    _ => continue,
                };
            }
        }
    }

    ui.stop();
}
