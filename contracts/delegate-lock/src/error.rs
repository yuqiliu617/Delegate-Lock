use ckb_std::error::SysError;

#[repr(i8)]
#[derive(Debug, PartialEq)]
pub enum Error {
    // System errors
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Custom errors
    ArgsInvalid,
    TypeIdCellNotFound,
    // Fallback error
    Unknown,
}

impl From<delegate_lock_helper::error::Error> for Error {
    fn from(err: delegate_lock_helper::error::Error) -> Self {
        match err {
            delegate_lock_helper::error::Error::HexDecoding => Self::Encoding,
            _ => Self::Unknown,
        }
    }
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        match err {
            SysError::IndexOutOfBound => Self::IndexOutOfBound,
            SysError::ItemMissing => Self::ItemMissing,
            SysError::LengthNotEnough(_) => Self::LengthNotEnough,
            SysError::Encoding => Self::Encoding,
            _ => Self::Unknown,
        }
    }
}
