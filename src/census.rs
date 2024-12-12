use anyhow::Result;
use babyjubjub_rs::Fr;
use ff_ce::hex;
use ff_ce::PrimeField;
use leanimt_rs::*;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigInt;
use num_bigint::BigUint;
use std::fmt::Debug;
use std::sync::LazyLock;

static ZERO: LazyLock<Fr> = LazyLock::new(|| Fr::from_str("0").unwrap());
static ONE: LazyLock<Fr> = LazyLock::new(|| Fr::from_str("1").unwrap());
static A: LazyLock<Fr> = LazyLock::new(|| Fr::from_str("168700").unwrap());
static D: LazyLock<Fr> = LazyLock::new(|| Fr::from_str("168696").unwrap());
static SUBORDER: LazyLock<BigInt> = LazyLock::new(|| {
    BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
    .unwrap()
});

fn poseidon_function(nodes: Vec<String>) -> String {
    use ark_bn254::Fr;

    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

    let input1 = Fr::from(nodes[0].parse::<BigUint>().unwrap());
    let input2 = Fr::from(nodes[1].parse::<BigUint>().unwrap());

    let hash = poseidon.hash(&[input1, input2]).unwrap();

    hash.to_string()
}
pub struct Identity(babyjubjub_rs::Point);
impl PartialEq for Identity {
    fn eq(&self, other: &Identity) -> bool {
        self.0.x == other.0.x && self.0.y == other.0.y
    }
}
impl Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "Point [{} {}]", self.0.x, self.0.y)
    }
}

impl Identity {
    fn on_curve(p: &babyjubjub_rs::Point) -> bool {
        use ff_ce::Field;

        let x2 = {
            let mut x2 = p.x;
            x2.square();
            x2
        };
        let y2 = {
            let mut y2 = p.y;
            y2.square();
            y2
        };

        let mut left = x2;
        left.mul_assign(&A);
        left.add_assign(&y2);

        let mut right = x2;
        right.mul_assign(&y2);
        right.mul_assign(&D);
        right.add_assign(&ONE);

        left == right
    }

    fn in_subgroup(p: &babyjubjub_rs::Point) -> bool {
        let res = p.mul_scalar(&SUBORDER);
        res.x == *ZERO && res.y == *ONE
    }

    pub fn try_from_compressed(s: &str) -> Result<Self> {
        let compressed = hex::decode(s).unwrap();
        let point = babyjubjub_rs::decompress_point(compressed.try_into().unwrap()).unwrap();
        assert!(Self::on_curve(&point) && Self::in_subgroup(&point));

        Ok(Self(point))
    }
    pub fn try_from_uncompressed(x: &str, y: &str) -> Result<Self> {
        let point = babyjubjub_rs::Point {
            x: babyjubjub_rs::Fr::from_str(x).unwrap(),
            y: babyjubjub_rs::Fr::from_str(y).unwrap(),
        };
        assert!(Self::on_curve(&point) && Self::in_subgroup(&point));

        Ok(Self(point))
    }
    pub fn to_uncompressed(&self) -> String {
        hex::encode(self.0.compress())
    }

    pub fn commitment(&self) -> String {
        let mut poseidon = Poseidon::<ark_bn254::Fr>::new_circom(2).unwrap();

        let nv = |x: Fr| {
            use ark_ff::PrimeField;
            let mut bytes = x.into_repr().0.map(|n| n.to_le_bytes().to_vec()).concat();
            bytes.reverse();
            ark_bn254::Fr::from_be_bytes_mod_order(&bytes)
        };

        let digest = poseidon.hash(&[nv(self.0.x), nv(self.0.y)]).unwrap();
        digest.to_string()
    }
}

pub fn census_merkle_root(identities: &[Identity]) -> Option<String> {
    let commitments: Vec<_> = identities.iter().map(|pbk| pbk.commitment()).collect();
    let mut lm = LeanIMT::new(poseidon_function, commitments).unwrap();
    lm.root()
}

#[cfg(test)]

mod test {

    use super::*;

    fn ids() -> [Identity; 3] {
        /*
        const id1 = new Identity("1")
        Identity {
            _privateKey: '1',
            _secretScalar: 1978755119068081247093963160279604962264019399313700915496711871956252953559n,
            _publicKey: [
              2454454600214856078988831413347908902755926762343652835672300056220098796444n,
              11602523348905956282108270948730557171172670800432155212780098470449477040649n
            ],
            _commitment: 18699903263915756199535533399390350858126023699350081471896734858638858200219n
          }
        */

        let id1 = Identity::try_from_uncompressed(
            "2454454600214856078988831413347908902755926762343652835672300056220098796444",
            "11602523348905956282108270948730557171172670800432155212780098470449477040649",
        )
        .unwrap();
        let id2 = Identity::try_from_uncompressed(
            "3620382800411485436164686979857588507564406034076655867743110797383733487338",
            "10645792713663945182273861002741840379653670778641283171122042137804873145550",
        )
        .unwrap();
        let id3 = Identity::try_from_uncompressed(
            "4885472904300052265212483680458692009781176225052241183446373535831606953266",
            "14226936848090988348595632203672434187685705193917601959687186005757430220738",
        )
        .unwrap();

        [id1, id2, id3]
    }

    #[test]
    fn test_compressed() {
        let [id1, id2, id3] = ids();

        assert_eq!(
            id1,
            Identity::try_from_compressed(&id1.to_uncompressed()).unwrap()
        );

        assert_eq!(
            id1.commitment(),
            "18699903263915756199535533399390350858126023699350081471896734858638858200219"
        );
        assert_eq!(
            id2.commitment(),
            "4446973358529698253939037684201229393105675634248270727935122282482202195132"
        );
        assert_eq!(
            id3.commitment(),
            "16658210975476022044027345155568543847928305944324616901189666478659011192021"
        );
    }

    #[test]
    fn test_census_root() {
        let [id1, id2, id3] = ids();

        let root = census_merkle_root(&[id1, id2, id3]).unwrap();
        assert_eq!(
            root,
            "8239982705883859505260185417990786909134720991686987543775753649428130088225"
        );
    }
}
