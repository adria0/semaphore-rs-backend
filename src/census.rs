use anyhow::{anyhow, Result};
use ark_bn254::Fr;
use leanimt_rs::*;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use std::str::FromStr;

fn string_to_biguint(num_str: &str) -> BigUint {
    num_str
        .parse()
        .expect("Failed to parse the string into BigUint")
}

fn poseidon_function(nodes: Vec<String>) -> String {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

    let input1 = Fr::from(string_to_biguint(&nodes[0]));
    let input2 = Fr::from(string_to_biguint(&nodes[1]));

    let hash = poseidon.hash(&[input1, input2]).unwrap();

    hash.to_string()
}
pub struct BjjPublicKey(ark_ed_on_bn254::EdwardsAffine);

impl BjjPublicKey {
    fn str_to_fq(s: &str) -> Result<ark_ed_on_bn254::Fq> {
        ark_ed_on_bn254::Fq::from_str(s).map_err(|_| anyhow!("deserialize error"))
    }
    #[cfg(test)]
    fn from_private_key(private_key: &[u8; 32]) -> Self {
        // note: this is not the way to do it, check the good way in
        // https://github.com/privacy-scaling-explorations/zk-kit/blob/main/packages/eddsa-poseidon/src/eddsa-poseidon-factory.ts

        use ark_ff::PrimeField;

        let g = ark_ed_on_bn254::EdwardsAffine::new(
            ark_ed_on_bn254::GENERATOR_X,
            ark_ed_on_bn254::GENERATOR_Y,
        );

        let k = ark_ed_on_bn254::Fr::from_le_bytes_mod_order(private_key);
        let p: ark_ed_on_bn254::EdwardsAffine = (g * k).into();
        BjjPublicKey(p)
    }
    pub fn try_from_string(x: &str, y: &str) -> Result<Self> {
        let point = ark_ed_on_bn254::EdwardsAffine::new(Self::str_to_fq(x)?, Self::str_to_fq(y)?);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(anyhow!("bad babyjubjub point"));
        }
        Ok(BjjPublicKey(point))
    }
    pub fn to_string(&self) -> (String, String) {
        (self.0.x.to_string(), self.0.y.to_string())
    }
    pub fn commitment(&self) -> String {
        let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
        let digest = poseidon.hash(&[self.0.x, self.0.y]).unwrap();
        digest.to_string()
    }
}

pub fn census_merkle_root(user_keys: &[BjjPublicKey]) -> Option<String> {
    let mut commitments: Vec<_> = user_keys.iter().map(|pbk| pbk.commitment()).collect();
    commitments.sort();
    let mut lm = LeanIMT::new(poseidon_function, commitments).unwrap();
    lm.root()
}

#[test]
fn census_test() {
    // test serialize & deserialize
    let bbj = BjjPublicKey::from_private_key(&[1u8; 32]);
    let bbj_serial = bbj.to_string();
    BjjPublicKey::try_from_string(&bbj_serial.0, &bbj_serial.1).unwrap();

    // test census
    let pbks = [
        BjjPublicKey::from_private_key(&[1u8; 32]),
        BjjPublicKey::from_private_key(&[2u8; 32]),
        BjjPublicKey::from_private_key(&[3u8; 32]),
        BjjPublicKey::from_private_key(&[4u8; 32]),
        BjjPublicKey::from_private_key(&[5u8; 32]),
        BjjPublicKey::from_private_key(&[6u8; 32]),
    ];
    println!("{}", census_merkle_root(&pbks).unwrap());
}
