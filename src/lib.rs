pub mod aes;
pub mod hash;

mod data;
mod fragment;

pub use data::FragData;
pub use fragment::Fragment;

use aes_gcm::aead::{Aead, AeadCore, KeyInit};
use fragment::FragmentHash;
use hash::Sha256;
use rayon::prelude::*;
use std::marker::PhantomData;

pub struct FragAES<T: AeadCore + Aead + KeyInit> {
    key: Vec<u8>,
    aes: PhantomData<T>,
    fragments: Vec<FragmentHash>,
}

impl<T: AeadCore + Aead + KeyInit> FragAES<T> {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            aes: PhantomData,
            fragments: Vec::new(),
        }
    }

    pub fn deploy(
        &mut self,
        mut data: FragData,
        k: usize,
        l: usize,
    ) -> Result<Vec<Fragment>, Box<dyn std::error::Error>> {
        let data_clone = data.data.clone();
        let updates = std::sync::Mutex::new(FragData::new());
        data_clone.par_iter().for_each(|(key, value)| {
            let enc_key = aes::derive_key(&self.key, &key.0, self.key.len());
            let aes = aes::AES::<T>::new(&enc_key);
            let encrypted_data = aes.encrypt(value, None).unwrap();
            updates
                .lock()
                .unwrap()
                .insert(encrypted_data, Some(key.clone()));
        });

        for (key, encrypted_data) in updates.into_inner().unwrap().data.into_iter() {
            data.update(&key, encrypted_data);
        }

        let frag_data_split = data.split(k, l);
        let fragments: Vec<Fragment> = frag_data_split
            .clone()
            .into_par_iter()
            .map(|frag| Fragment::new(frag.clone()))
            .collect();
        self.fragments = frag_data_split
            .into_par_iter()
            .map(|frag| FragmentHash::new(Sha256::new(&frag.as_bytes())))
            .collect();
        Ok(fragments)
    }

    pub fn insert(&mut self, fragment: &Fragment) {
        self.fragments.push(fragment.fragment_hash());
    }

    pub fn update(&mut self, fragment: &Fragment) {
        if let Some(index) = self.find_fragment_index(fragment) {
            self.fragments[index] = fragment.fragment_hash();
        }
    }

    pub fn add(&mut self, hash: FragmentHash) {
        self.fragments.push(hash);
    }

    pub fn get_fragment_count(&self) -> usize {
        self.fragments.len()
    }

    pub fn verify_fragments(&self, fragments: &[Fragment]) -> bool {
        if fragments.len() != self.fragments.len() {
            return false;
        }

        fragments
            .iter()
            .zip(self.fragments.iter())
            .all(|(fragment, fragment_hash)| fragment.verify(fragment_hash))
    }

    pub fn clear_fragments(&mut self) {
        self.fragments.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.fragments.is_empty()
    }

    pub fn get_key_size(&self) -> usize {
        self.key.len()
    }

    pub fn find_fragment_index(&self, fragment: &Fragment) -> Option<usize> {
        self.fragments
            .iter()
            .position(|hash| hash.verify(*fragment.get_hash()))
    }

    pub fn get_fragment_hash(&self, index: usize) -> Option<&FragmentHash> {
        self.fragments.get(index)
    }

    pub fn remove_fragment(&mut self, index: usize) -> Option<FragmentHash> {
        if index < self.fragments.len() {
            Some(self.fragments.remove(index))
        } else {
            None
        }
    }

    pub fn contains_fragment(&self, fragment: &Fragment) -> bool {
        self.fragments
            .iter()
            .any(|hash| hash.verify(*fragment.get_hash()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::Aes256Gcm;

    #[test]
    fn test_new() {
        let key = vec![0u8; 32];
        let frag_aes = FragAES::<Aes256Gcm>::new(&key);
        assert_eq!(frag_aes.key, key);
        assert!(frag_aes.fragments.is_empty());
    }

    #[test]
    fn test_deploy() {
        let key = aes::generate_key(32);
        let mut frag_aes = FragAES::<Aes256Gcm>::new(&key);
        let mut data = FragData::new();
        data.insert(vec![1, 2, 3], None);
        let fragments = frag_aes.deploy(data, 2, 3).unwrap();
        assert!(!frag_aes.fragments.is_empty());
        assert_eq!(fragments.len(), frag_aes.fragments.len());
    }

    #[test]
    fn test_helper_functions() {
        let key = aes::generate_key(32);
        let mut frag_aes = FragAES::<Aes256Gcm>::new(&key);
        let mut data = FragData::new();
        data.insert(vec![1, 2, 3], None);
        let fragments = frag_aes.deploy(data, 2, 3).unwrap();

        assert_eq!(frag_aes.get_fragment_count(), fragments.len());
        assert!(!frag_aes.is_empty());
        assert_eq!(frag_aes.get_key_size(), 32);

        assert!(frag_aes.verify_fragments(&fragments));

        assert!(frag_aes.contains_fragment(&fragments[0]));
        assert_eq!(frag_aes.find_fragment_index(&fragments[0]), Some(0));

        let removed_hash = frag_aes.remove_fragment(0).unwrap();
        assert_eq!(frag_aes.get_fragment_count(), fragments.len() - 1);

        frag_aes.add(removed_hash);
        assert_eq!(frag_aes.get_fragment_count(), fragments.len());

        frag_aes.clear_fragments();
        assert!(frag_aes.is_empty());
    }
}
