pub mod json;
pub mod table;

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Json,
    #[value(name = "json-minify")]
    JsonMinify,
    Table,
}

impl OutputFormat {
    pub fn is_minify(self) -> bool {
        self == OutputFormat::JsonMinify
    }
}
