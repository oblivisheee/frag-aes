use crate::hash::Sha256;
use std::collections::HashMap;
#[derive(Default, Clone)]
pub struct FragData {
    pub data: HashMap<Sha256, Vec<u8>>,
}

impl FragData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, data: Vec<u8>, hash: Option<Sha256>) {
        let key = hash.unwrap_or_else(|| Sha256::new(&data));
        self.data.insert(key, data);
    }

    pub fn get(&self, hash: &Sha256) -> Option<&Vec<u8>> {
        self.data.get(hash)
    }

    pub fn remove(&mut self, hash: &Sha256) -> Option<Vec<u8>> {
        self.data.remove(hash)
    }

    pub fn contains(&self, hash: &Sha256) -> bool {
        self.data.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn update(&mut self, hash: &Sha256, data: Vec<u8>) -> Option<Vec<u8>> {
        self.data.insert(*hash, data)
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        self.data.values().flat_map(|v| v.iter().cloned()).collect()
    }

    pub fn split(&self, k: usize, l: usize) -> Vec<FragData> {
        let mut result = Vec::new();
        let mut iter = self.data.iter();

        for _ in 0..k {
            let mut new_frag = FragData::new();
            for _ in 0..l {
                if let Some((key, value)) = iter.next() {
                    new_frag.insert(value.clone(), Some(*key));
                } else {
                    break;
                }
            }
            if !new_frag.is_empty() {
                result.push(new_frag);
            } else {
                break;
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let frag_data = FragData::new();
        assert!(frag_data.is_empty());
    }

    #[test]
    fn test_insert_and_get() {
        let mut frag_data = FragData::new();
        let data = vec![1, 2, 3];
        let hash = Sha256::new(&data);
        frag_data.insert(data.clone(), Some(hash));
        assert_eq!(frag_data.get(&hash), Some(&data));
    }

    #[test]
    fn test_remove() {
        let mut frag_data = FragData::new();
        let data = vec![1, 2, 3];
        let hash = Sha256::new(&data);
        frag_data.insert(data.clone(), Some(hash));
        assert_eq!(frag_data.remove(&hash), Some(data));
        assert!(frag_data.is_empty());
    }

    #[test]
    fn test_contains() {
        let mut frag_data = FragData::new();
        let data = vec![1, 2, 3];
        let hash = Sha256::new(&data);
        frag_data.insert(data, Some(hash));
        assert!(frag_data.contains(&hash));
    }

    #[test]
    fn test_len() {
        let mut frag_data = FragData::new();
        frag_data.insert(vec![1, 2, 3], None);
        frag_data.insert(vec![4, 5, 6], None);
        assert_eq!(frag_data.len(), 2);
    }

    #[test]
    fn test_update() {
        let mut frag_data = FragData::new();
        let data1 = vec![1, 2, 3];
        let hash = Sha256::new(&data1);
        frag_data.insert(data1, Some(hash));
        let data2 = vec![4, 5, 6];
        assert_eq!(frag_data.update(&hash, data2.clone()), Some(vec![1, 2, 3]));
        assert_eq!(frag_data.get(&hash), Some(&data2));
    }

    #[test]
    fn test_split() {
        let mut frag_data = FragData::new();
        for i in 0..10 {
            frag_data.insert(vec![i], None);
        }
        let split = frag_data.split(3, 3);
        assert_eq!(split.len(), 3);
        assert_eq!(split[0].len(), 3);
        assert_eq!(split[1].len(), 3);
        assert_eq!(split[2].len(), 3);
    }
}
