use crate::hash::Sha256;
use crate::FragData;
use hex::ToHex;
pub struct Fragment {
    pub body: FragData,
    hash: Sha256,
}

impl Fragment {
    pub fn new(body: FragData) -> Self {
        Self {
            body: body.clone(),
            hash: Sha256::new(&body.as_bytes()),
        }
    }

    pub fn verify(&self, fh: &FragmentHash) -> bool {
        fh.verify(self.hash)
    }

    pub fn get_hash(&self) -> &Sha256 {
        &self.hash
    }

    pub fn update_body(&mut self, new_body: FragData) {
        self.body = new_body.clone();
        self.hash = Sha256::new(&self.body.as_bytes());
    }
    pub fn fragment_hash(&self) -> FragmentHash {
        FragmentHash::new(self.hash.clone())
    }
}

pub struct FragmentHash {
    hash: Sha256,
}

impl FragmentHash {
    pub fn new(hash: Sha256) -> Self {
        Self { hash }
    }

    pub fn verify(&self, hash: Sha256) -> bool {
        self.hash == hash
    }

    pub fn from_fragment(fragment: &Fragment) -> Self {
        Self {
            hash: fragment.hash.clone(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.hash.as_bytes()
    }
}

impl ToHex for FragmentHash {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.hash.encode_hex()
    }
    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.hash.encode_hex_upper()
    }
}
