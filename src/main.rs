use std::{
    ffi::OsString,
    io::{self, IsTerminal},
    process::ExitCode,
};

use ipnedir::{
    app::{self, SystemClock},
    platform::NativeCollector,
    public::{self, PublicWorkers},
    render::Style,
};

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let style = Style::detect(
        stdout.is_terminal(),
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var_os("TERM").is_some_and(|term| term == "dumb"),
    );
    let status = app::run(
        &args,
        || NativeCollector,
        || PublicWorkers::new(public::http::lookup),
        &mut SystemClock,
        style,
        &mut stdout.lock(),
        &mut stderr.lock(),
    );
    ExitCode::from(status)
}
