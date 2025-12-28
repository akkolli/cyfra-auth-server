use std::io::{stdin, Write};
// use term_size;

pub fn clear_screen(header: Option<&str>) -> Result<(), std::io::Error> {
    // Print the ANSI escape code to clear the screen
        print!("\x1B[2J\x1B[1;1H");
        display_text(header.unwrap_or(""));
        std::io::stdout().flush()
}

pub fn display_text(text: &str) {
    print!("{}", text);
    std::io::stdout().flush().unwrap();
}

pub fn input_into_string(input_variable: &mut String) -> std::io::Result<usize> {
    stdin().read_line(input_variable)
}

pub fn get_input(prompt: &str) -> Result<String, std::io::Error> {

    display_text(prompt);

    let mut ans = String::new();

    input_into_string(&mut ans)?;

    Ok(ans)

}

//get_input with trimming
pub fn get_trimmed_input(prompt: &str) -> Result<String, std::io::Error> {

    display_text(prompt);

    let mut ans = String::new();

    input_into_string(&mut ans)?;

    Ok(ans.trim().to_owned())

}


// pub fn move_cursor_down(height: Option<usize>) {

//     match term_size::dimensions() {
//         Some((_, rows)) => {
//             let mut amount: usize = 0;
//             if height.unwrap_or(0) < rows {
//                 amount = rows - height.unwrap_or(0);
//             } else {
//                 amount = rows;
//             }
//             print!("\x1b[{};1H", amount)},
//         None => {},
//     };
// }
