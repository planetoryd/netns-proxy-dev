use thiserror::Error;

// Errors are only typed, when necessary

#[derive(Error, Debug)]
#[error("Deviance from a configuration plan, or the configuration is faulty")]
pub struct DevianceError;

#[derive(Error, Debug)]
#[error("Something is missing, and it can be handled")]
pub struct MissingError;

#[derive(Error, Debug)]
#[error("Errors that shouldn't happen")]
pub struct ProgrammingError;
