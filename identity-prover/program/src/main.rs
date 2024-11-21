#![no_main]

use cfdkim::{verify_email_with_public_key, DkimPublicKey};
use mailparse::{parse_mail, MailHeaderMap};
use sha2::{Digest, Sha256};
use sp1_zkvm::io::{commit, commit_slice, read, read_vec};

// Define the program entrypoint
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Read input values from the prover
    let from_domain = read::<String>();
    let raw_email = read_vec();
    let public_key_type = read::<String>();
    let public_key_vec = read_vec();

    // Parse the email and construct the DKIM public key
    let email = parse_mail(&raw_email).unwrap();
    let public_key = DkimPublicKey::from_vec_with_type(&public_key_vec, &public_key_type);

    // Calculate hash of the public key
    let mut hasher = Sha256::new();
    hasher.update(public_key_vec);
    let public_key_hash = hasher.finalize();

    // Calculate hash of the from domain
    let mut hasher = Sha256::new();
    hasher.update(from_domain.as_bytes());
    let from_domain_hash = hasher.finalize();

    // Extract recipient email and calculate voter ID hash
    let to = email.headers.get_first_value("To").unwrap();
    let mut hasher = Sha256::new();
    hasher.update(to.as_bytes());
    let voter_id = hasher.finalize();

    // Commit the hashes as public values
    commit_slice(&from_domain_hash);
    commit_slice(&public_key_hash);
    commit_slice(&voter_id);

    // Verify the DKIM signature and commit the result
    let result = verify_email_with_public_key(&from_domain, &email, &public_key).unwrap();
    if let Some(_) = &result.error() {
        commit(&false);
    } else {
        commit(&true);
    }
}
