/// Circom utilities
use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ff::BigInteger256;
use ark_groth16::VerifyingKey;
use num_bigint::BigUint;
use serde_derive::Deserialize;

use anyhow::{anyhow, Result};

type SerializedG1 = [String; 3];
type SerializedG2 = [[String; 2]; 3];

#[derive(Deserialize, PartialEq, Eq)]
struct SemaphoreVerifierKeys {
    vk_alpha_1: SerializedG1,
    vk_beta_2: SerializedG2,
    vk_gamma_2: SerializedG2,
    vk_delta_2: Vec<SerializedG2>,
    #[serde(rename = "IC")]
    ic: Vec<Vec<SerializedG1>>,
}

pub fn deserialize(json: &str, level: usize) -> Result<VerifyingKey<Bn254>> {
    let svk: SemaphoreVerifierKeys = serde_json::from_str(json).unwrap();

    let gamma_abc_g1: Result<Vec<_>> = svk.ic[level].iter().map(deser_g1).collect();

    Ok(VerifyingKey {
        alpha_g1: deser_g1(&svk.vk_alpha_1)?,
        beta_g2: deser_g2(&svk.vk_beta_2)?,
        gamma_g2: deser_g2(&svk.vk_gamma_2)?,
        delta_g2: deser_g2(&svk.vk_delta_2[level])?,
        gamma_abc_g1: gamma_abc_g1?,
    })
}
pub fn fq_from_str(s: &str) -> Result<Fq> {
    let bn = BigUint::from_str(s)?;
    let bn256 = BigInteger256::try_from(bn).map_err(|_| anyhow!("unserialize fq"))?;
    Ok(bn256.into())
}

pub fn fr_from_str(s: &str) -> Result<Fr> {
    let bn = BigUint::from_str(s)?;
    let bn256 = BigInteger256::try_from(bn).map_err(|_| anyhow!("unserialize fr"))?;
    Ok(bn256.into())
}

fn deser_g1(g1: &SerializedG1) -> Result<G1Affine> {
    Ok(G1Affine::from(G1Projective::new(
        fq_from_str(&g1[0])?,
        fq_from_str(&g1[1])?,
        fq_from_str(&g1[2])?,
    )))
}

fn deser_g2(g2: &SerializedG2) -> Result<G2Affine> {
    let x = Fq2::new(fq_from_str(&g2[0][0])?, fq_from_str(&g2[0][1])?);
    let y = Fq2::new(fq_from_str(&g2[1][0])?, fq_from_str(&g2[1][1])?);
    let z = Fq2::new(fq_from_str(&g2[2][0])?, fq_from_str(&g2[2][1])?);
    Ok(G2Affine::from(G2Projective::new(x, y, z)))
}
