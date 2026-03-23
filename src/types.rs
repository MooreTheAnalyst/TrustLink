use soroban_sdk::{contracttype, contracterror, Address, Env, String};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    NotFound = 4,
    AlreadyRevoked = 5,
    DuplicateAttestation = 6,
    InvalidValidFrom = 7,
    InvalidExpiration = 8,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestationStatus {
    Valid,
    Expired,
    Revoked,
    Pending,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Attestation {
    pub id: String,
    pub issuer: Address,
    pub subject: Address,
    pub claim_type: String,
    pub timestamp: u64,
    pub expiration: Option<u64>,
    pub revoked: bool,
    pub valid_from: Option<u64>,
}

impl Attestation {
    pub fn get_status(&self, current_time: u64) -> AttestationStatus {
        if let Some(vf) = self.valid_from {
            if current_time < vf {
                return AttestationStatus::Pending;
            }
        }
        if self.revoked {
            return AttestationStatus::Revoked;
        }
        if let Some(exp) = self.expiration {
            if current_time >= exp {
                return AttestationStatus::Expired;
            }
        }
        AttestationStatus::Valid
    }

    pub fn generate_id(
        env: &Env,
        issuer: &Address,
        subject: &Address,
        claim_type: &String,
        timestamp: u64,
    ) -> String {
        use soroban_sdk::xdr::ToXdr;
        use soroban_sdk::Bytes;

        let mut data = Bytes::new(env);

        let issuer_xdr = issuer.clone().to_xdr(env);
        data.append(&issuer_xdr);

        let subject_xdr = subject.clone().to_xdr(env);
        data.append(&subject_xdr);

        let claim_bytes = claim_type.clone().to_xdr(env);
        data.append(&claim_bytes);

        let ts_bytes = timestamp.to_be_bytes();
        data.append(&Bytes::from_array(env, &ts_bytes));

        let hash = env.crypto().sha256(&data);
        let hex_chars: &[u8] = b"0123456789abcdef";
        let hash_bytes = hash.to_array();

        let mut arr = [0u8; 64];
        for (i, byte) in hash_bytes.iter().enumerate() {
            arr[i * 2] = hex_chars[(byte >> 4) as usize];
            arr[i * 2 + 1] = hex_chars[(byte & 0xf) as usize];
        }
        String::from_bytes(env, &arr)
    }
}
