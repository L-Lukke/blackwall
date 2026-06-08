use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone)]
pub struct DidDocument {
    id: String,
    verification_methods: Vec<VerificationMethod>,
}

#[derive(Debug, Clone)]
struct VerificationMethod {
    id: String,
    controller: String,
    public_key_multibase: String,
    public_key_bytes: [u8; 32],
}

pub trait DidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, String>;
}

pub struct DidKeyResolver;

impl DidResolver for DidKeyResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, String> {
        let Some(encoded) = did.strip_prefix("did:key:z") else {
            return Err("unsupported_did_method".to_string());
        };

        let decoded = base58_decode(encoded)?;
        if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
            return Err("unsupported_did_key_multicodec".to_string());
        }

        let public_key_bytes =
            <[u8; 32]>::try_from(&decoded[2..34]).map_err(|_| "bad_did_key_length".to_string())?;
        let key_id = format!("{}#key-1", did);

        Ok(DidDocument {
            id: did.to_string(),
            verification_methods: vec![VerificationMethod {
                id: key_id,
                controller: did.to_string(),
                public_key_multibase: format!("z{}", encoded),
                public_key_bytes,
            }],
        })
    }
}

impl DidKeyResolver {
    pub fn resolve_verification_key(
        &self,
        did: &str,
        verification_method_id: &str,
    ) -> Result<VerifyingKey, String> {
        let document = self.resolve(did)?;
        if document.id != did {
            return Err("did_document_id_mismatch".to_string());
        }

        let Some(method) = document
            .verification_methods
            .iter()
            .find(|method| method.id == verification_method_id)
        else {
            return Err("verification_method_not_found".to_string());
        };

        if method.controller != did {
            return Err("verification_method_controller_mismatch".to_string());
        }
        if !method.public_key_multibase.starts_with('z') {
            return Err("unsupported_verification_key_encoding".to_string());
        }

        VerifyingKey::from_bytes(&method.public_key_bytes).map_err(|_| "bad_did_key".to_string())
    }
}

fn base58_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.strip_prefix('z').unwrap_or(input);
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = vec![0];

    for ch in input.bytes() {
        let Some(mut carry) = alphabet.iter().position(|&c| c == ch).map(|p| p as u32) else {
            return Err("bad_base58_character".to_string());
        };

        for byte in bytes.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }

        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    for ch in input.bytes() {
        if ch == b'1' {
            bytes.insert(0, 0);
        } else {
            break;
        }
    }

    Ok(bytes)
}
