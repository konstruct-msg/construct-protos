//! Fixed-seed hybrid / ML-KEM / X25519 material for CTH1 golden vectors.
//!
//! Seeds are the only secret this program holds. Output is JSON on stdout,
//! consumed by `scripts/gen_history_snapshot_vectors.py`.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use ml_dsa::{B32, Keypair as _, MlDsa65, Signer as _, SigningKey as MlDsaSigningKey};
#[allow(deprecated)]
use ml_kem::{
    Encapsulate, EncapsulationKey, ExpandedKeyEncoding, Generate, KeyExport, MlKem1024,
    array::Array,
};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use sha2::{Digest, Sha256};

/// SHA-256 counter RNG that implements the rand_core 0.10 traits ml-kem 0.3 wants.
struct SeedRng {
    seed: [u8; 32],
    block: [u8; 32],
    off: usize,
    counter: u64,
}

impl SeedRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            block: [0; 32],
            off: 32,
            counter: 0,
        }
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(self.seed);
        h.update(self.counter.to_le_bytes());
        self.block.copy_from_slice(&h.finalize());
        self.counter += 1;
        self.off = 0;
    }
}

impl TryRng for SeedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for b in dst.iter_mut() {
            if self.off >= 32 {
                self.refill();
            }
            *b = self.block[self.off];
            self.off += 1;
        }
        Ok(())
    }
}

impl TryCryptoRng for SeedRng {}
use x25519_dalek::{PublicKey, StaticSecret};

const HYBRID_ED25519_SEED: [u8; 32] = [0xA1; 32];
const HYBRID_MLDSA_SEED: [u8; 32] = [0xA2; 32];
const OFFERING_IDENTITY_SEED: [u8; 32] = [0x11; 32];
const RECEIVER_IDENTITY_SEED: [u8; 32] = [0x22; 32];
const SENDER_EPH_SEED: [u8; 32] = [0x33; 32];
const RECEIVER_EPH_SEED: [u8; 32] = [0x44; 32];
const MLKEM_KEYGEN_SEED: [u8; 32] = [0xB1; 32];
const MLKEM_ENCAP_SEED: [u8; 32] = [0xB2; 32];
const KYBER_KEY_ID: u32 = 7;
const WRONG_KYBER_KEY_ID: u32 = 8;

const SNAPSHOT_ID: [u8; 16] = [0xAA; 16];
const USER_ID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

fn x25519_pair(seed: [u8; 32]) -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::from(seed);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

fn device_id_raw(identity_pub: &[u8]) -> [u8; 16] {
    let hash = Sha256::digest(identity_pub);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

fn hybrid_keys() -> (Vec<u8>, Vec<u8>) {
    let ed = SigningKey::from_bytes(&HYBRID_ED25519_SEED);
    let mldsa = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(HYBRID_MLDSA_SEED));
    let mldsa_pk = mldsa.verifying_key().encode();
    let mut sk = Vec::with_capacity(2016);
    sk.extend_from_slice(&ed.to_bytes());
    sk.extend_from_slice(&HYBRID_MLDSA_SEED);
    sk.extend_from_slice(mldsa_pk.as_slice());
    let mut pk = Vec::with_capacity(1984);
    pk.extend_from_slice(ed.verifying_key().as_bytes());
    pk.extend_from_slice(mldsa_pk.as_slice());
    (sk, pk)
}

fn hybrid_sign(hybrid_sk: &[u8], message: &[u8]) -> Vec<u8> {
    let ed_seed: [u8; 32] = hybrid_sk[..32].try_into().unwrap();
    let mldsa_seed: [u8; 32] = hybrid_sk[32..64].try_into().unwrap();
    let ed = SigningKey::from_bytes(&ed_seed);
    let ed_sig = ed.sign(message);
    let mldsa = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(mldsa_seed));
    let mldsa_sig = mldsa.try_sign(message).expect("ml-dsa sign");
    let mut out = Vec::with_capacity(3373);
    out.extend_from_slice(&ed_sig.to_bytes());
    out.extend_from_slice(mldsa_sig.encode().as_slice());
    out
}

fn ed25519_only_sig(hybrid_sk: &[u8], message: &[u8]) -> Vec<u8> {
    let ed_seed: [u8; 32] = hybrid_sk[..32].try_into().unwrap();
    let ed = SigningKey::from_bytes(&ed_seed);
    let ed_sig = ed.sign(message);
    let mut out = vec![0u8; 3373];
    out[..64].copy_from_slice(&ed_sig.to_bytes());
    out
}

fn mlkem_keypair(seed: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut rng = SeedRng::new(seed);
    #[allow(deprecated)]
    let dk = ml_kem::DecapsulationKey::<MlKem1024>::generate_from_rng(&mut rng);
    let ek: &EncapsulationKey<MlKem1024> = dk.encapsulation_key();
    let pk = ek.to_bytes().to_vec();
    #[allow(deprecated)]
    let sk = dk.to_expanded_bytes().to_vec();
    (pk, sk)
}

fn mlkem_encapsulate(pk: &[u8], seed: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let arr: &Array<u8, _> = pk.try_into().expect("ml-kem pk size");
    let ek = EncapsulationKey::<MlKem1024>::new(arr).expect("kyber pk");
    let mut rng = SeedRng::new(seed);
    let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
    (ct.to_vec(), ss.to_vec())
}

fn hkdf_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf");
    okm
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (hybrid_sk, hybrid_pk) = hybrid_keys();
    if args.len() == 3 && (args[1] == "sign" || args[1] == "sign-ed") {
        let msg = hex::decode(&args[2]).expect("message hex");
        let sig = if args[1] == "sign-ed" {
            ed25519_only_sig(&hybrid_sk, &msg)
        } else {
            hybrid_sign(&hybrid_sk, &msg)
        };
        println!("{}", hex::encode(sig));
        return;
    }
    let (offering_sk, offering_pk) = x25519_pair(OFFERING_IDENTITY_SEED);
    let (receiver_sk, receiver_pk) = x25519_pair(RECEIVER_IDENTITY_SEED);
    let (sender_eph_sk, sender_eph_pk) = x25519_pair(SENDER_EPH_SEED);
    let (_receiver_eph_sk, receiver_eph_pk) = x25519_pair(RECEIVER_EPH_SEED);

    let offering_id = device_id_raw(offering_pk.as_bytes());
    let receiver_id = device_id_raw(receiver_pk.as_bytes());

    let (kyber_pk, kyber_sk) = mlkem_keypair(MLKEM_KEYGEN_SEED);
    let (kem_ct, kem_ss) = mlkem_encapsulate(&kyber_pk, MLKEM_ENCAP_SEED);

    let ecdh_file = sender_eph_sk.diffie_hellman(&receiver_pk);
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ecdh_file.as_bytes());
    ikm.extend_from_slice(&kem_ss);
    let file_key = hkdf_key(
        &ikm,
        b"construct_history_file_v1",
        &SNAPSHOT_ID,
    );

    let chunk_plain = b"cth1-chunk0";
    let mut aad = Vec::new();
    aad.extend_from_slice(&SNAPSHOT_ID);
    aad.extend_from_slice(&USER_ID);
    aad.extend_from_slice(&0u32.to_le_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: chunk_plain,
                aad: &aad,
            },
        )
        .expect("seal");
    let mut chunk0 = Vec::with_capacity(12 + sealed.len());
    chunk0.extend_from_slice(&[0u8; 12]);
    chunk0.extend_from_slice(&sealed);

    let fp = Sha256::digest(
        [offering_pk.as_bytes().as_slice(), hybrid_pk.as_slice()].concat(),
    );

    let json = serde_like(
        &hybrid_sk,
        &hybrid_pk,
        offering_sk.as_bytes(),
        offering_pk.as_bytes(),
        receiver_sk.as_bytes(),
        receiver_pk.as_bytes(),
        sender_eph_sk.as_bytes(),
        sender_eph_pk.as_bytes(),
        receiver_eph_pk.as_bytes(),
        &offering_id,
        &receiver_id,
        &kyber_pk,
        &kyber_sk,
        &kem_ct,
        &kem_ss,
        &file_key,
        chunk_plain,
        &chunk0,
        fp.as_slice(),
    );
    print!("{json}");
}

/// Tiny JSON object writer so this crate does not take serde.
fn serde_like(
    hybrid_sk: &[u8],
    hybrid_pk: &[u8],
    offering_sk: &[u8],
    offering_pk: &[u8],
    receiver_sk: &[u8],
    receiver_pk: &[u8],
    sender_eph_sk: &[u8],
    sender_eph_pk: &[u8],
    receiver_eph_pk: &[u8],
    offering_id: &[u8],
    receiver_id: &[u8],
    kyber_pk: &[u8],
    kyber_sk: &[u8],
    kem_ct: &[u8],
    kem_ss: &[u8],
    file_key: &[u8],
    chunk_plain: &[u8],
    chunk0: &[u8],
    qr_fp: &[u8],
) -> String {
    let h = |b: &[u8]| hex::encode(b);
    let mut s = String::from("{\n");
    let mut field = |k: &str, v: &str| {
        s.push_str(&format!("  \"{k}\": \"{v}\",\n"));
    };
    field("hybrid_ed25519_seed", &h(&HYBRID_ED25519_SEED));
    field("hybrid_mldsa_seed", &h(&HYBRID_MLDSA_SEED));
    field("hybrid_secret", &h(hybrid_sk));
    field("hybrid_public", &h(hybrid_pk));
    field("offering_identity_secret", &h(offering_sk));
    field("offering_identity_public", &h(offering_pk));
    field("receiver_identity_secret", &h(receiver_sk));
    field("receiver_identity_public", &h(receiver_pk));
    field("sender_eph_secret", &h(sender_eph_sk));
    field("sender_eph_public", &h(sender_eph_pk));
    field("receiver_eph_public", &h(receiver_eph_pk));
    field("offering_device_id_raw", &h(offering_id));
    field("receiver_device_id_raw", &h(receiver_id));
    field("kyber_public", &h(kyber_pk));
    field("kyber_secret", &h(kyber_sk));
    field("kem_ct", &h(kem_ct));
    field("kem_ss", &h(kem_ss));
    field("file_channel_key", &h(file_key));
    field("chunk0_plaintext", &h(chunk_plain));
    field("chunk0_combined", &h(chunk0));
    field("qr_fp", &h(qr_fp));
    s.push_str(&format!("  \"kyber_key_id\": {KYBER_KEY_ID},\n"));
    s.push_str(&format!(
        "  \"wrong_kyber_key_id\": {WRONG_KYBER_KEY_ID}\n"
    ));
    s.push('}');
    s
}

#[allow(dead_code)]
fn _sign_export(hybrid_sk: &[u8], tagged: &[u8]) -> String {
    hex::encode(hybrid_sign(hybrid_sk, tagged))
}

#[allow(dead_code)]
fn _ed_only(hybrid_sk: &[u8], tagged: &[u8]) -> String {
    hex::encode(ed25519_only_sig(hybrid_sk, tagged))
}
