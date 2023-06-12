use core::fmt::{Display};
use std::io;
use std::io::Write;

use libc;

pub mod draw;

pub struct UI<T: Display, F: Fn(usize, usize, &Vec<T>)> {
    initial_config: libc::termios,
    rows: usize,
    cols: usize,
    model: Vec<T>,
    render: F,
}

impl<T: Display, F: Fn(usize, usize, &Vec<T>)> UI<T, F> {
    pub fn new(model: Vec<T>, render: F) -> Self {
        let (rows, cols) = Self::terminal_size();

        let mut config = libc::termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_cc: [0; 20],
            c_ispeed: 0,
            c_ospeed: 0,
        };
        unsafe { libc::tcgetattr(1, &mut config) };

        UI {
            initial_config: config,
            rows: rows,
            cols: cols,
            model: model,
            render: render,
        }
    }

    fn terminal_size() -> (usize, usize) {
        let size = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
        unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &size) };

        (size.ws_row as usize, size.ws_col as usize)
    }

//    fn resize(&mut self) {
//        let (rows, cols) = Self::terminal_size();
//
//        self.rows = rows;
//        self.cols = cols;
//        self.render();
//    }

    pub fn add_data(&mut self, datum: T) {
        self.model.push(datum);
        self.render();
    }

    pub fn start(&self) {
        let mut config = self.initial_config;
        config.c_lflag = config.c_lflag & !libc::ECHO & !libc::ICANON;
        unsafe { libc::tcsetattr(1, libc::TCSANOW, &config) };

        // Switch to alternate buffer
        print!("[?1049h");
        // Clean-up buffer
        print!("[2J");
        // Hide cursor
        print!("[?25l");

        self.render();
    }

    pub fn stop(&self) {
        // Clean-up buffer
        print!("[2J");
        // Exit alternate buffer
        print!("[?1049l");
        // Show cursor
        print!("[?25h");

        unsafe { libc::tcsetattr(1, libc::TCSANOW, &self.initial_config) };
    }

    fn render(&self) {
        (self.render)(self.rows, self.cols, &self.model);

        io::stdout().flush().unwrap();
    }
}
