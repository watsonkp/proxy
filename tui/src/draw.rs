use core::fmt::{Display};

pub trait LogEntry {
    fn timestamp(&self) -> String;
    fn to_lines(&self) -> Vec<String>;
}

pub fn line_numbers(origin: (usize, usize), rows: usize) {
    let rows = rows - origin.0;
    for i in 0..rows {
        print!("[{};1H{}", origin.0 + i, origin.0 + i);
    }
}

pub fn fill(origin: (usize, usize), rows: usize, cols: usize, background: Option<Colour>) {
    let style = Style::new(None, background);
    let row = style.style_string(&" ".repeat(cols));
    
    for i in 0..rows {
        print!("[{};{}H{}", origin.0 + i, origin.1, row);
    }
}

pub fn list<T: Display>(origin: (usize, usize), data: &Vec<T>) {
    for (i, datum) in data.iter().enumerate() {
        print!("[{};{}H[1m[38;2;{};{};{};48;2;{};{};{}m{}[0m",
            origin.0 + i,
            origin.1,
            0x54, 0x27, 0x8f, 0xcb, 0xc9, 0xe2,
            datum);
    }
}

pub fn log<T: LogEntry>(origin: (usize, usize), entries: &Vec<T>) {
    let (row, col) = origin;

    let mut written_lines = 0;
    for entry in entries {
        let lines = entry.to_lines();
        for (j, line) in lines.iter().enumerate() {
            print!("[{};{}H[1m[38;2;{};{};{};48;2;{};{};{}m{}[0m",
                origin.0 + written_lines + j,
                origin.1,
                0x54, 0x27, 0x8f, 0xcb, 0xc9, 0xe2,
                line);
        }
        written_lines += lines.len();
    }
}

pub fn status_line(rows: usize, cols: usize) {
    print!("[{};1H[47m{}[0m", rows, " ".repeat(cols));
    print!("[{};1H[30;47m{} x {}[0m", rows, rows, cols);
}

pub enum Colour {
    TrueColour { red: u32, green: u32, blue: u32 },
}

struct Style {
    foreground: Option<Colour>,
    background: Option<Colour>,
}

impl Style {
    pub fn new(foreground: Option<Colour>, background: Option<Colour>) -> Self {
        return Style {
            foreground,
            background,
        }
    }

    fn get_style(self) -> String {
        let mut style = String::new();

        // Add foreground colour style if it was specified
        if let Some(colour) = self.foreground {
            match colour {
                Colour::TrueColour { red, green, blue } => style.push_str(&format!("38;2;{red};{green};{blue}")),
            }
        }

        // Add background colour style if it was specified
        if let Some(colour) = self.background {
            if style != "" {
                style.push(';');
            }
            match colour {
                Colour::TrueColour { red, green, blue } => style.push_str(&format!("48;2;{red};{green};{blue}")),
            }
        }

        style
    }

    fn style_string(self, s: &str) -> String {
        let style = self.get_style();

        if style != "" {
            format!("[{}m{}[0m", style, s)
        } else {
            s.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coloured_style() {
        let style = Style::new(Some(Colour::TrueColour { red: 84, green: 39, blue: 143 }), Some(Colour::TrueColour { red: 203, green: 201, blue: 226 }));
        assert_eq!(style.get_style(), "38;2;84;39;143;48;2;203;201;226m")
    }
}
