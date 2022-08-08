use clap::ArgMatches;
use std::io::{Read, Write};

use crate::Error;

pub struct AppState {
    pub in_stream: Box<dyn Read>,
    pub out_stream: Box<dyn Write>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Create an AppState with default settings
    pub fn new() -> Self {
        Self {
            in_stream: Box::new(std::io::stdin()),
            out_stream: Box::new(std::io::stdout()),
        }
    }

    pub fn read_stream(&mut self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::<u8>::new();
        let _cnt = self.in_stream.read_to_end(&mut bytes).map_err(Error::BadIO);
        Ok(bytes)
    }

    pub fn write_stream(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let _ = self.out_stream.write_all(bytes).map_err(Error::BadIO);
        Ok(())
    }
}

impl TryFrom<&ArgMatches> for AppState {
    type Error = Error;
    fn try_from(_value: &ArgMatches) -> Result<Self, Self::Error> {
        let app_state = AppState::default();
        Ok(app_state)
    }
}
