use std::io;
use std::thread;
use std::io::Read;
use std::sync::mpsc;

use tui::UI;
use tui::draw;
use tui::draw::Colour::TrueColour;
use parse;
use proxy;

fn read_commands(sender: mpsc::Sender<String>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 1];
        loop {
            match io::stdin().read(&mut buf) {
                Ok(_) => {
                    if let Ok(command) = String::from_utf8(Vec::from(buf)) {
                        if command == "q" {
                            match sender.send(command) {
                                Ok(_) => {},
                                Err(_) => {},
                            };
                        }
                    }
                },
                Err(_) => { },
            };
        }
    })
}

fn main() {
    let render = |rows, cols, model: &Vec<parse::Request>| {
        draw::fill((1,1), rows, cols, Some(TrueColour { red: 0xcb, green: 0xc9, blue: 0xe2 }));
        draw::log((1,1), model);
        draw::status_line(rows, cols);
    };

    let mut ui = UI::new(Vec::new(), render);
    ui.start();

    let (proxy_tx, proxy_rx) = mpsc::channel();
    proxy::start("127.0.0.1:7878", proxy_tx);

    let (key_tx, key_rx) = mpsc::channel();
    read_commands(key_tx);

    loop {
        match proxy_rx.try_recv() {
            Ok(received) => ui.add_data(received),
            Err(_) => {},
        };

        match key_rx.try_recv() {
            Ok(key) => if key == "q" { break; },
            Err(_) => {},
        };
    }

    ui.stop();
}
