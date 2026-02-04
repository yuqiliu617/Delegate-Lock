use ckb_lock_helper::error::Error as HelperError;
use ckb_std::error::SysError;

#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    Unknown = 30,
    WrongWitnessArgs,
    WrongPubkey,
    WrongSignatureFormat,
    WrongSignature,
}

impl From<HelperError> for Error {
    fn from(value: HelperError) -> Self {
        match value {
            HelperError::IndexOutOfBound => Error::IndexOutOfBound,
            HelperError::ItemMissing => Error::ItemMissing,
            HelperError::LengthNotEnough => Error::LengthNotEnough,
            HelperError::Encoding => Error::Encoding,
            HelperError::Unknown => Error::Unknown,
            HelperError::WrongWitnessArgs => Error::WrongWitnessArgs,
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
            SysError::Unknown(_) => Self::Unknown,
        }
    }
}
