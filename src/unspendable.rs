use bitcoin::{key::{rand::Rng, Secp256k1}, secp256k1::{self, SecretKey}, PublicKey};

use crate::errors::UnspendableKeyError;

const H: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// TODO: Each taptree will have a different random unspendable key. We need both participants 
// to use the same unspendable keys. We can use a deterministic RNG and share the seed at the 
// beginning between the participants to generate the same keys. 
pub fn unspendable_key<R: Rng + ?Sized>(rng: &mut R) -> Result<PublicKey, UnspendableKeyError> {
    // Initialize the secp256k1 context
    let secp = Secp256k1::new();

    // Generate a random scalar (secret key) r using a cryptographically secure RNG
    let r = SecretKey::new(rng);

    // Convert H value to byte array
    let h = hex::decode(H).map_err(|_| UnspendableKeyError::HexDecodeError)?;

    // Get H as a point on the curve represented using a PublicKey
    let h_point = secp256k1::PublicKey::from_slice(&h).map_err(|_| UnspendableKeyError::FailedToBuildUnspendableKey {reason: "Invalid H value".to_string()})?;

    // Compute r * G, which gives a point on the curve
    let r_times_g = secp256k1::PublicKey::from_secret_key(&secp, &r);

    // Add H and r * G together to compute H + r * G
    let result = h_point.combine(&r_times_g).map_err(|_| UnspendableKeyError::FailedToBuildUnspendableKey {reason: "Point addition failed".to_string()})?;

    Ok(PublicKey::new(result))
}
