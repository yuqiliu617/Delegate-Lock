use k256::ecdsa::hazmat::bits2field;
use k256::ecdsa::signature::Result;
use k256::ecdsa::{Error, RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::bigint::CheckedAdd;
use k256::elliptic_curve::ops::{Invert, LinearCombination, Reduce};
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::{AffinePoint, Curve, FieldBytesEncoding, PrimeField, ProjectivePoint};
use k256::{Scalar, Secp256k1};

/// Equivalent to VerifyingKey::recover_from_prehash but the final verification process is removed.
/// Ref: https://github.com/RustCrypto/signatures/issues/751.
#[allow(non_snake_case)]
pub fn recover_from_prehash(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> Result<VerifyingKey> {
    let (r, s) = signature.split_scalars();
    let z = <Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
        &bits2field::<Secp256k1>(prehash)?,
    );

    let mut r_bytes = r.to_repr();
    if recovery_id.is_x_reduced() {
        match Option::<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>::from(
            <Secp256k1 as k256::elliptic_curve::Curve>::Uint::decode_field_bytes(&r_bytes)
                .checked_add(&Secp256k1::ORDER),
        ) {
            Some(restored) => r_bytes = restored.encode_field_bytes(),
            // No reduction should happen here if r was reduced
            None => return Err(Error::new()),
        };
    }
    let R = AffinePoint::<Secp256k1>::decompress(&r_bytes, u8::from(recovery_id.is_y_odd()).into());

    if R.is_none().into() {
        return Err(Error::new());
    }

    let R = ProjectivePoint::<Secp256k1>::from(R.unwrap());
    let r_inv = *r.invert();
    let u1 = -(r_inv * z);
    let u2 = r_inv * *s;
    let pk = ProjectivePoint::<Secp256k1>::lincomb(
        &ProjectivePoint::<Secp256k1>::GENERATOR,
        &u1,
        &R,
        &u2,
    );
    let vk = VerifyingKey::from_affine(pk.into())?;
    Ok(vk)
}
