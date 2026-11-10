pub mod api;
pub mod cli;
pub mod config;
pub mod engine;
pub mod import_common;
pub mod mapping;
pub mod models;
pub mod openredaction;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod variables;

pub fn run_cli() -> i32 {
    cli::run()
}
