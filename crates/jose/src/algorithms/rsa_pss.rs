// RSA-PSS implementation using aegaeon-crypto
// RFC 7518 compliant (PS256, PS384, PS512)

use super::{Algorithm, AlgorithmError};
use base64::{engine::general_purpose::STANDARD, Engine as _};

/// RSA-PSS signing key wrapper
pub struct RsaPssSigner {
    inner: aegaeon_crypto::signing::RsaPssSigner,
    algorithm: Algorithm,
}

impl RsaPssSigner {
    /// Create a new RSA-PSS signer from PEM-encoded private key
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError`] when `algorithm` is not an RSA-PSS variant,
    /// the PEM body cannot be decoded, or the key cannot be parsed.
    pub fn from_pem(pem: &str, algorithm: Algorithm) -> Result<Self, AlgorithmError> {
        // Validate algorithm
        match algorithm {
            Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {}
            _ => {
                return Err(AlgorithmError::Unsupported(format!(
                    "{} is not an RSA-PSS algorithm",
                    algorithm.as_str()
                )))
            }
        }

        // Parse PEM - need to extract the base64 content between headers
        let pem_lines: Vec<&str> = pem.lines().collect();
        let mut b64_content = String::new();
        let mut in_key = false;

        for line in pem_lines {
            if line.contains("BEGIN") {
                in_key = true;
                continue;
            }
            if line.contains("END") {
                break;
            }
            if in_key {
                b64_content.push_str(line);
            }
        }

        // Decode base64
        let der_bytes = STANDARD
            .decode(&b64_content)
            .map_err(|e| AlgorithmError::InvalidKey(format!("Failed to decode PEM: {e:?}")))?;

        let inner = aegaeon_crypto::signing::RsaPssSigner::from_pkcs8(&der_bytes)
            .map_err(|e| AlgorithmError::InvalidKey(format!("Failed to parse RSA key: {e}")))?;

        Ok(Self { inner, algorithm })
    }

    /// Create a new RSA-PSS signer from DER-encoded private key
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError`] when `algorithm` is not an RSA-PSS variant
    /// or the key cannot be parsed.
    pub fn from_der(der: &[u8], algorithm: Algorithm) -> Result<Self, AlgorithmError> {
        // Validate algorithm
        match algorithm {
            Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {}
            _ => {
                return Err(AlgorithmError::Unsupported(format!(
                    "{} is not an RSA-PSS algorithm",
                    algorithm.as_str()
                )))
            }
        }

        let inner = aegaeon_crypto::signing::RsaPssSigner::from_pkcs8(der)
            .map_err(|e| AlgorithmError::InvalidKey(format!("Failed to parse RSA key: {e}")))?;

        Ok(Self { inner, algorithm })
    }

    /// Sign a message
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError`] when signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        match self.algorithm {
            Algorithm::PS256 => self
                .inner
                .sign_pss256(message)
                .map_err(|e| AlgorithmError::SigningFailed(format!("{e}"))),
            Algorithm::PS384 => self
                .inner
                .sign_pss384(message)
                .map_err(|e| AlgorithmError::SigningFailed(format!("{e}"))),
            Algorithm::PS512 => self
                .inner
                .sign_pss512(message)
                .map_err(|e| AlgorithmError::SigningFailed(format!("{e}"))),
            _ => unreachable!("Algorithm validated in constructor"),
        }
    }

    /// Get the public key in DER format
    #[must_use]
    pub fn public_key_der(&self) -> Vec<u8> {
        self.inner.public_key_der()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test RSA key pair for PS256 testing (2048-bit)
    const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDphTRTLa33rpSQ
0GPIg2ZhrV5zZ2q6Jhfj5GRRClJqjJjgxPqRtPbGOO/PA1JTjXa8LrLuOBDGJx4i
+pa1bemHSc4+gB6BBftMWrtJ0s0bcOc7ca2EzeMSY0QMNjus3WRT05YRhiIZmKeu
J9DpNLZrv+SYSYO9FgQTKUUbUqei8x+dn1qZKomYibkVnxCZ/dDB45cwicvkKe52
ZJSsD2i+S7BMsIJgy4U03+zgK6bHiBbTzLnROfIj0vS8OvasgDRMuNN3lHuxESsL
Tdh6088bdQ7w39Qn1+HtCUiYvUbJhY9oZQ92FUrD82owyRvCLEnJw5cCjc3UGu5v
F0PSIjQbAgMBAAECggEABih/sQnbEFVZ/jQ8Fo51HHJRs51na/sBMSNVnnxZxTGO
R68qJHT4ZQgdEbg2tHA5vjnXVGzqFFQ+nchjHRCYG7Kq27XyYSHQrd8VhnbdiUQB
0H82q1/oToJnEv7MSBObIyUSJ8XdfX2ZYwBbhAZQITtM1NPZMT+ihrtnmbbcAyjj
AE1ZwX4BCoOFD08xCbQ3EvIIerNqdwhw/+TQjnTL/nXKg3gyXqhTlTWRGac5SjDs
TWDSGtGalFY/b15Q2oDxtkR58zSau6lHOCyZA4kQFg5iKokeQCLC4lf9E6RcJogE
UcNjVrjc7AEOGdwgR1xU0uJO0FWsrk0Iq7ZMjf21cQKBgQD/iP5FS6xIYPKlAlPZ
UcwOtL2X71yhPPG1Eh9T8N4z1eYDil/50OBNBQr49j0I51Y1OC/IMV8/SGAttqsp
elH+FWQqPdNRT5LuBGSel/6iJcfeFHiWbCvbmG7ROA3LiKs11c6Tloo3ky8kJGK+
t6DZspF7BIo+tuhLLQGOPXAvpwKBgQDp8fVgzjofn0c9TNsDhIchnBJnK8cK42SS
YrCY0x1gRRyyM3XiaQHeMkkUBieRb3ZeSIowBEhxDojGnPBNj7KaNef9nlqsTzVx
VRAR9SV47fJlKRxCPrejjwvjTwlRRAtmo9sXpAKOxDd0uFEOMD87jzhKaGvbYVWp
n22nvcAGbQKBgQD3HvHf6+3B1VfzMgwKx6sSscIEtCwdlkWeOddoIzGQaZRW6jQk
8NZqRa011VRzTt20/BBhhzW4inLQ4q4mn6+5i9BhdYbuRIkwe7kfEpjjEKx4Xc28
kwHbDVBmLtJQemww1QNBAb3LPyDA0Btam1UIE0PT9zEGs3Z0dSLi/xGGUwKBgFj1
qiJSqWWG8tcLl6jhx2TvbUwQKJMqXv8PSioC9YO7JCtbSDN9TLmKk6FqqbczFGbL
3MhfiJB9P2OPIA3OW9MqNnqJsd8eC6t59i9t8f7nNKplFJrYMIqghZu9XUSqxE8W
deSqeFKDqLbYs/HaROFIF9armIAGpkVnG5KSpCeNAoGBAMlPKkrud1n7Bw9Q1wd3
HG9LIaTZvhsQ052SFkA1X/Sp5LRkmUrSAkBXyhxo0EmEEqmjyOo8n4+Tnj16bYcP
D4MIhlPri0MEevhyT4XT5d5waSlX779ChSupyflIVK3CQvZF5vJuDkX4ugiE+6Uo
dXhxpIsS9twuhYpCdx9IlS32
-----END PRIVATE KEY-----";

    #[test]
    fn test_rsa_pss_signs_ps256() -> Result<(), Box<dyn std::error::Error>> {
        let signer = RsaPssSigner::from_pem(TEST_RSA_PRIVATE_KEY, Algorithm::PS256)?;
        let message = b"test message";
        let signature = signer.sign(message)?;

        // Independent signing-correctness oracle: aws-lc-rs pure-Rust PSS verify
        // over the signer's own SPKI. This checks the signing path only; it is
        // NOT the production HACL verification path
        // (jws.rs verify_rsa_pss_sha256 -> ffi::verify_rsa(PS256)).
        let spki = signer.public_key_der();
        aegaeon_crypto::signature::verify_rsa_pss_sha256(&spki, message, &signature)
            .expect("PS256 signature must verify against the signer's own public key");
        Ok(())
    }

    #[test]
    fn test_rsa_pss_signs_ps384_ps512() -> Result<(), Box<dyn std::error::Error>> {
        let message = b"test message for all algorithms";

        // No pure-Rust PS384/PS512 verify oracle exists, so assert the RSA
        // signature-length invariant instead: a 2048-bit key yields a 256-byte
        // signature regardless of the PSS hash variant.
        let signer = RsaPssSigner::from_pem(TEST_RSA_PRIVATE_KEY, Algorithm::PS384)?;
        let signature = signer.sign(message)?;
        assert_eq!(
            signature.len(),
            256,
            "PS384 over a 2048-bit key yields a 256-byte signature"
        );

        let signer = RsaPssSigner::from_pem(TEST_RSA_PRIVATE_KEY, Algorithm::PS512)?;
        let signature = signer.sign(message)?;
        assert_eq!(
            signature.len(),
            256,
            "PS512 over a 2048-bit key yields a 256-byte signature"
        );
        Ok(())
    }

    #[test]
    fn test_invalid_algorithm() {
        // Should fail with non-PSS algorithm
        assert!(RsaPssSigner::from_pem(TEST_RSA_PRIVATE_KEY, Algorithm::RS256).is_err());
    }
}
