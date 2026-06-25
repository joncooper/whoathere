use std::collections::BTreeMap;

use whoathere_vault_api::{ArtifactRef, CacheKeyError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineReceipt {
    pub quarantine_id: String,
    pub artifact: ArtifactRef,
    pub cache_object_key: String,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotedCacheObject {
    pub artifact: ArtifactRef,
    pub cache_object_key: String,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheStoreError {
    InvalidDigest(CacheKeyError),
    EmptyPayload,
    UnsupportedDigestVerification,
    DigestMismatch,
    QuarantineNotFound,
    ObjectAlreadyPromoted,
    PromotedObjectNotFound,
    PromotedObjectKeyMismatch,
    PromotedObjectArtifactMismatch,
}

impl CacheStoreError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidDigest(error) => error.reason_code(),
            Self::EmptyPayload => "cache_payload_empty",
            Self::UnsupportedDigestVerification => "cache_digest_verification_unsupported",
            Self::DigestMismatch => "cache_digest_mismatch",
            Self::QuarantineNotFound => "cache_quarantine_not_found",
            Self::ObjectAlreadyPromoted => "cache_object_already_promoted",
            Self::PromotedObjectNotFound => "cache_promoted_object_not_found",
            Self::PromotedObjectKeyMismatch => "cache_promoted_object_key_mismatch",
            Self::PromotedObjectArtifactMismatch => "cache_promoted_object_artifact_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheObject {
    artifact: ArtifactRef,
    cache_object_key: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct InMemoryCacheStore {
    quarantined: BTreeMap<String, CacheObject>,
    promoted: BTreeMap<String, CacheObject>,
    next_quarantine_id: u64,
}

impl InMemoryCacheStore {
    pub fn new() -> Self {
        Self {
            next_quarantine_id: 1,
            ..Self::default()
        }
    }

    pub fn quarantine(
        &mut self,
        artifact: ArtifactRef,
        bytes: Vec<u8>,
    ) -> Result<QuarantineReceipt, CacheStoreError> {
        if bytes.is_empty() {
            return Err(CacheStoreError::EmptyPayload);
        }
        let cache_object_key = artifact
            .cache_object_key()
            .map_err(CacheStoreError::InvalidDigest)?;
        verify_payload_digest(&artifact.digest, &bytes)?;
        let quarantine_id = format!("quarantine-{}", self.next_quarantine_id);
        self.next_quarantine_id += 1;
        let object = CacheObject {
            artifact: artifact.clone(),
            cache_object_key: cache_object_key.clone(),
            bytes,
        };
        let byte_len = object.bytes.len();
        self.quarantined.insert(quarantine_id.clone(), object);
        Ok(QuarantineReceipt {
            quarantine_id,
            artifact,
            cache_object_key,
            byte_len,
        })
    }

    pub fn promote(&mut self, quarantine_id: &str) -> Result<PromotedCacheObject, CacheStoreError> {
        let object = self
            .quarantined
            .remove(quarantine_id)
            .ok_or(CacheStoreError::QuarantineNotFound)?;
        if self.promoted.contains_key(&object.cache_object_key) {
            return Err(CacheStoreError::ObjectAlreadyPromoted);
        }
        let promoted = PromotedCacheObject {
            artifact: object.artifact.clone(),
            cache_object_key: object.cache_object_key.clone(),
            byte_len: object.bytes.len(),
        };
        self.promoted
            .insert(object.cache_object_key.clone(), object);
        Ok(promoted)
    }

    pub fn promoted_bytes(&self, cache_object_key: &str) -> Option<&[u8]> {
        self.promoted
            .get(cache_object_key)
            .map(|object| object.bytes.as_slice())
    }

    pub fn promoted_bytes_for_artifact(
        &self,
        artifact: &ArtifactRef,
        cache_object_key: &str,
    ) -> Result<&[u8], CacheStoreError> {
        let expected_key = artifact
            .cache_object_key()
            .map_err(CacheStoreError::InvalidDigest)?;
        if expected_key != cache_object_key {
            return Err(CacheStoreError::PromotedObjectKeyMismatch);
        }
        let object = self
            .promoted
            .get(cache_object_key)
            .ok_or(CacheStoreError::PromotedObjectNotFound)?;
        if object.artifact != *artifact {
            return Err(CacheStoreError::PromotedObjectArtifactMismatch);
        }
        Ok(object.bytes.as_slice())
    }
}

fn verify_payload_digest(digest: &str, bytes: &[u8]) -> Result<(), CacheStoreError> {
    let Some((algorithm, expected)) = digest.split_once(':') else {
        return Err(CacheStoreError::InvalidDigest(
            CacheKeyError::MissingSeparator,
        ));
    };
    match algorithm {
        "sha256" => {
            let actual = sha256_hex(bytes);
            if expected.eq_ignore_ascii_case(&actual) {
                Ok(())
            } else {
                Err(CacheStoreError::DigestMismatch)
            }
        }
        _ => Err(CacheStoreError::UnsupportedDigestVerification),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut hash: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            words[index] = small_sigma1(words[index - 2])
                .wrapping_add(words[index - 7])
                .wrapping_add(small_sigma0(words[index - 15]))
                .wrapping_add(words[index - 16]);
        }

        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];

        for index in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }

    hash.iter()
        .map(|word| format!("{word:08x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma0(value: u32) -> u32 {
    value.rotate_right(2) ^ value.rotate_right(13) ^ value.rotate_right(22)
}

fn big_sigma1(value: u32) -> u32 {
    value.rotate_right(6) ^ value.rotate_right(11) ^ value.rotate_right(25)
}

fn small_sigma0(value: u32) -> u32 {
    value.rotate_right(7) ^ value.rotate_right(18) ^ (value >> 3)
}

fn small_sigma1(value: u32) -> u32 {
    value.rotate_right(17) ^ value.rotate_right(19) ^ (value >> 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC_DIGEST: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_OBJECT_KEY: &str =
        "blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ZERO_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn quarantines_then_promotes_inert_bytes() {
        let mut store = InMemoryCacheStore::new();
        let artifact = sample_artifact(ABC_DIGEST);
        let receipt = store.quarantine(artifact.clone(), b"abc".to_vec()).unwrap();
        assert_eq!(receipt.cache_object_key, ABC_OBJECT_KEY);
        assert_eq!(receipt.byte_len, 3);

        let promoted = store.promote(&receipt.quarantine_id).unwrap();
        assert_eq!(promoted.artifact, artifact);
        assert_eq!(promoted.cache_object_key, ABC_OBJECT_KEY);
        assert_eq!(store.promoted_bytes(ABC_OBJECT_KEY).unwrap(), b"abc");
        assert_eq!(
            store
                .promoted_bytes_for_artifact(&artifact, ABC_OBJECT_KEY)
                .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn promoted_lookup_requires_exact_artifact_and_key() {
        let mut store = InMemoryCacheStore::new();
        let artifact = sample_artifact(ABC_DIGEST);
        let receipt = store.quarantine(artifact.clone(), b"abc".to_vec()).unwrap();
        store.promote(&receipt.quarantine_id).unwrap();

        let wrong_key = store
            .promoted_bytes_for_artifact(
                &artifact,
                "blobs/sha256/0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap_err();
        assert_eq!(
            wrong_key.reason_code(),
            "cache_promoted_object_key_mismatch"
        );

        let mut wrong_artifact = artifact.clone();
        wrong_artifact.name = "other".to_string();
        let wrong_artifact_error = store
            .promoted_bytes_for_artifact(&wrong_artifact, ABC_OBJECT_KEY)
            .unwrap_err();
        assert_eq!(
            wrong_artifact_error.reason_code(),
            "cache_promoted_object_artifact_mismatch"
        );
    }

    #[test]
    fn promoted_lookup_fails_closed_when_object_missing() {
        let store = InMemoryCacheStore::new();
        let error = store
            .promoted_bytes_for_artifact(&sample_artifact(ABC_DIGEST), ABC_OBJECT_KEY)
            .unwrap_err();
        assert_eq!(error.reason_code(), "cache_promoted_object_not_found");
    }

    #[test]
    fn sha256_implementation_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_mismatch_never_enters_quarantine() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(sample_artifact(ZERO_DIGEST), b"bytes".to_vec())
            .unwrap_err();
        assert_eq!(error.reason_code(), "cache_digest_mismatch");
    }

    #[test]
    fn unsupported_digest_verification_fails_closed() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(
                sample_artifact(
                    "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                ),
                b"bytes".to_vec(),
            )
            .unwrap_err();
        assert_eq!(error.reason_code(), "artifact_digest_algorithm_unsupported");
    }

    #[test]
    fn invalid_digest_never_enters_quarantine() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(sample_artifact("sha256:../escape"), b"bytes".to_vec())
            .unwrap_err();
        assert_eq!(
            error.reason_code(),
            "artifact_digest_contains_unsafe_characters"
        );
    }

    #[test]
    fn empty_payload_fails_closed() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(sample_artifact(ABC_DIGEST), Vec::new())
            .unwrap_err();
        assert_eq!(error.reason_code(), "cache_payload_empty");
    }

    #[test]
    fn unknown_quarantine_cannot_promote() {
        let mut store = InMemoryCacheStore::new();
        let error = store.promote("missing").unwrap_err();
        assert_eq!(error.reason_code(), "cache_quarantine_not_found");
    }

    fn sample_artifact(digest: &str) -> ArtifactRef {
        ArtifactRef {
            ecosystem: "npm".to_string(),
            name: "fixture".to_string(),
            version: "1.0.0".to_string(),
            digest: digest.to_string(),
            source: "inert-test-fixture".to_string(),
        }
    }
}
