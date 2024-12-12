use crate::vk::{deserialize, fq_from_str, fr_from_str};
use anyhow::Result;
use ark_bn254::Fr;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ff::BigInteger256;
use ark_ff::QuadExtField;
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use num_bigint::BigUint;
use tiny_keccak::Hasher;
use tiny_keccak::Keccak;

#[derive(Clone)]
pub struct PublicInputs {
    pub merkle_root: String,
    pub nullifier: String,
    pub message: Vec<u8>,
    pub scope: Vec<u8>,
}

/// Make content safe to be used in message and scope
/// Mimic of semaphore's _hash function
///    uint256(keccak256(abi.encodePacked(message))) >> 8
pub fn safe_hash(input: &[u8]) -> Fr {
    // keccak the input string
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    // make subgroup safe
    let n = BigUint::from_bytes_be(&digest[0..31]);

    BigInteger256::try_from(n).unwrap().into()
}

/// Verify a proof
pub fn verify_semaphore_proof(
    merkle_tree_depth: usize,
    vk_json: &str,
    proof: &[String; 8],
    public_inputs: &PublicInputs,
) -> Result<bool> {
    let vk = deserialize(vk_json, merkle_tree_depth - 1)?;
    let prepared_vk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    let proof = Proof {
        a: G1Affine {
            x: fq_from_str(&proof[0])?,
            y: fq_from_str(&proof[1])?,
            infinity: false,
        },
        b: G2Affine {
            x: QuadExtField {
                c0: fq_from_str(&proof[3])?,
                c1: fq_from_str(&proof[2])?,
            },
            y: QuadExtField {
                c0: fq_from_str(&proof[5])?,
                c1: fq_from_str(&proof[4])?,
            },
            infinity: false,
        },
        c: G1Affine {
            x: fq_from_str(&proof[6])?,
            y: fq_from_str(&proof[7])?,
            infinity: false,
        },
    };

    let public_inputs = [
        fr_from_str(&public_inputs.merkle_root)?,
        fr_from_str(&public_inputs.nullifier)?,
        safe_hash(&public_inputs.message),
        safe_hash(&public_inputs.scope),
    ];

    let verified =
        Groth16::<Bn254>::verify_with_processed_vk(&prepared_vk, &public_inputs, &proof).unwrap();

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::BigInteger;
    use std::str::FromStr;

    #[test]
    pub fn test_hash() {
        let message = BigInteger256::from_str("2").unwrap();
        let message_hash =
            "113682330006535319932160121224458771213356533826860247409332700812532759386";

        assert_eq!(
            safe_hash(&message.to_bytes_be()),
            fr_from_str(message_hash).unwrap()
        );
    }

    #[test]
    // Note: the proof is taken from
    //   "Should not validate the same proof for an onchain group twice"
    //   generated in semaphore source
    pub fn test_verify_proof() -> Result<()> {
        let merkle_tree_depth = 12;
        let vk_json = include_str!("../resources/verification-keys.json");
        let proof = [
            "3124073622236616456833396570356705156646073617929792953660812743611960024190".into(),
            "11674593079837824239506141664778422059519704820958312743297425608713245420595".into(),
            "7713593111503797875083485400820120663028319233891959159458423952236575706609".into(),
            "13918742698649602494560780635556261031458297729038932250925604643453249264786".into(),
            "4613101685097457670047817259042475037350388787609714430990301793107996667409".into(),
            "17259635958185732611521307880893285119726843931898239890115044320004960927756".into(),
            "4123698559833481083195750955920855321118417082763738715668302474011286156175".into(),
            "20945401992348007733224283573172486537439478102034563286602289058123220654542".into(),
        ];

        let message = BigInteger256::from_str("2").unwrap().to_bytes_be();
        // note: scope does not have to be the mt root, it's just a (lazy) concidence here
        let scope = BigInteger256::from_str(
            "5407869850562333726769604095330004527418297248703115046359956082084347839061",
        )
        .unwrap()
        .to_bytes_be();

        let public_inputs = PublicInputs {
            merkle_root:
                "5407869850562333726769604095330004527418297248703115046359956082084347839061"
                    .into(),
            nullifier:
                "6861077843010628185829686827205507386432657129784465342569728589877241230741"
                    .into(),
            message,
            scope,
        };

        let verified =
            verify_semaphore_proof(merkle_tree_depth, vk_json, &proof, &public_inputs).unwrap();
        assert!(verified);

        {
            // fails with bad merkle root
            let mut public_inputs = public_inputs.clone();
            public_inputs.merkle_root =
                "5407869850562333726769604095330004527418297248703115046359956082084347839062"
                    .into();
            let verified =
                verify_semaphore_proof(merkle_tree_depth, vk_json, &proof, &public_inputs).unwrap();
            assert!(!verified);
        }

        {
            // fails with bad proof
            let mut proof = proof.clone();
            proof[0] =
                "3124073622236616456833396570356705156646073617929792953660812743611960024191"
                    .into();
            let verified =
                verify_semaphore_proof(merkle_tree_depth, vk_json, &proof, &public_inputs).unwrap();
            assert!(!verified);
        }

        {
            // fails with bad merkle_tree_depth
            let verified =
                verify_semaphore_proof(merkle_tree_depth + 1, vk_json, &proof, &public_inputs)
                    .unwrap();
            assert!(!verified);
        }

        Ok(())
    }
}
