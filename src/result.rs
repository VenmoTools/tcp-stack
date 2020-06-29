pub type Result<T> = std::result::Result<T, Error>;


#[derive(Debug)]
pub enum Error {
    StdIOError(std::io::Error),
    WriteError(etherparse::WriteError),
    ReadError(etherparse::ReadError),
}

macro_rules! impl_error {
    ($err:ty,$en:ident) => {
        impl From<$err> for Error {
            fn from(err: $err) -> Self {
                Error::$en(err)
            }
        }
    };
}

impl_error!(std::io::Error,StdIOError);
impl_error!(etherparse::WriteError,WriteError);
impl_error!(etherparse::ReadError,ReadError);
