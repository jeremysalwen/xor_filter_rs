use linked_hash_set::LinkedHashSet;
use num::Zero;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::marker::PhantomData;
use std::ops::BitXor;
use std::ops::BitXorAssign;

pub struct XorFilter<T: Hash, F: FingerprintType = u16, H: BuildHasher + Default = RandomState> {
    size: u64, // Note this is 1/3 the length of B, i.e. c/3 in the original paper.
    b: Vec<F>,
    hash_builder: H,
    _phantomt: PhantomData<T>,
}

fn fast_random_integer_reduce(x: u64, range: u64) -> u64 {
    (((x as u128) * (range as u128)) >> 64) as u64
}

pub trait FingerprintType:
    BitXor<Self, Output = Self> + BitXorAssign<Self> + PartialEq + Copy + Zero
{
    fn from(x: u64) -> Self;
}
impl FingerprintType for u16 {
    fn from(x: u64) -> Self {
        x as u16
    }
}
impl FingerprintType for u8 {
    fn from(x: u64) -> Self {
        x as u8
    }
}

fn ones(v: &[u64], start: usize, end: usize) -> LinkedHashSet<usize> {
    v[start..end]
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| if c == 1 { Some(i) } else { None })
        .collect()
}

fn remove_from_occupancy_table(
    occupancy_codes: &mut [u64],
    occupancy_counts: &mut [u64],
    hash: u64,
    index: usize,
    queue: &mut LinkedHashSet<usize>,
) {
    occupancy_codes[index as usize] ^= hash;
    occupancy_counts[index as usize] -= 1;

    if occupancy_counts[index as usize] == 1 {
        queue.insert(index as usize);
    }
}

fn pop_queues<T: Eq + Hash>(
    queue1: &mut LinkedHashSet<T>,
    queue2: &mut LinkedHashSet<T>,
    queue3: &mut LinkedHashSet<T>,
) -> Option<T> {
    queue1
        .pop_front()
        .or_else(|| queue2.pop_front().or_else(|| queue3.pop_front()))
}

//From<u64> needs to be revisited since u16 does not satisfy.
impl<T: Hash, F: FingerprintType, H: BuildHasher + Default> XorFilter<T, F, H> {
    fn hash(&self, value: &T) -> u64 {
        let mut hasher = self.hash_builder.build_hasher();
        value.hash(&mut hasher);
        return hasher.finish();
    }

    // The derivation of all the hash values from the u64 was not
    // explained in the paper.  This is based on the C++ implementation
    // code, since I don't trust myself to implement fast and nonbiased
    // techniques on my own.
    fn derive_fingerprint(hash: u64) -> F {
        F::from(hash & (hash >> 32))
    }

    fn derive_h(&self, hash: u64) -> (u64, u64, u64) {
        let h1 = fast_random_integer_reduce(hash.wrapping_shl(0), self.size);
        let h2 = fast_random_integer_reduce(hash.wrapping_shl(21), self.size) + self.size;
        let h3 = fast_random_integer_reduce(hash.wrapping_shl(42), self.size) + 2 * self.size;
        return (h1, h2, h3);
    }

    pub fn new<'a, I>(size: usize, elements: &'a I) -> Self
    where
        &'a I: IntoIterator<Item = &'a T>,
        T: 'a,
    {
        let c: usize = (size * 3) as usize;
        loop {
            let mut filter = Self {
                size: size as u64,
                b: vec![F::zero(); c],
                hash_builder: H::default(),
                _phantomt: PhantomData {},
            };

            // First we calculate the occupancy code (xor of all hashes) and occupancy count
            let mut occupancy_codes: Vec<u64> = vec![0; c];
            let mut occupancy_counts: Vec<u64> = vec![0; c];
            let mut num_elements = 0;
            for element in elements {
                let hash = filter.hash(element);
                let (h1, h2, h3) = filter.derive_h(hash);

                // TODO: To me this is sketchy, reusing the hash here like this.
                // Will need to think about this more closely.
                let occupancy_code = hash;
                occupancy_codes[h1 as usize] ^= occupancy_code;
                occupancy_codes[h2 as usize] ^= occupancy_code;
                occupancy_codes[h3 as usize] ^= occupancy_code;

                occupancy_counts[h1 as usize] += 1;
                occupancy_counts[h2 as usize] += 1;
                occupancy_counts[h3 as usize] += 1;

                num_elements += 1;
            }

            let mut queue1: LinkedHashSet<usize> = ones(&occupancy_counts[..], 0, size as usize);
            let mut queue2: LinkedHashSet<usize> =
                ones(&occupancy_counts[..], 1 * size as usize, 2 * size as usize);
            let mut queue3: LinkedHashSet<usize> =
                ones(&occupancy_counts[..], 2 * size as usize, 3 * size as usize);

            let mut stack = Vec::<(usize, u64)>::with_capacity(num_elements);
            while let Some(index) = pop_queues(&mut queue1, &mut queue2, &mut queue3) {
                let hash = occupancy_codes[index];
                let (h1, h2, h3) = filter.derive_h(hash);
                remove_from_occupancy_table(
                    &mut occupancy_codes,
                    &mut occupancy_counts[..],
                    hash,
                    h1 as usize,
                    &mut queue1,
                );
                remove_from_occupancy_table(
                    &mut occupancy_codes,
                    &mut occupancy_counts[..],
                    hash,
                    h2 as usize,
                    &mut queue2,
                );
                remove_from_occupancy_table(
                    &mut occupancy_codes,
                    &mut occupancy_counts[..],
                    hash,
                    h3 as usize,
                    &mut queue3,
                );
                stack.push((index, hash));
            }

            if num_elements == stack.len() {
                // Success!
                for (i, hash) in stack {
                    let (h1, h2, h3) = filter.derive_h(hash);
                    filter.b[i] = XorFilter::<T, F, H>::derive_fingerprint(hash)
                        ^ filter.b[h1 as usize]
                        ^ filter.b[h2 as usize]
                        ^ filter.b[h3 as usize];
                }
                return filter;
            }
        }
    }

    pub fn contains(&self, value: &T) -> bool {
        let hash = self.hash(value);
        let fingerprint = Self::derive_fingerprint(hash);
        let (h1, h2, h3) = self.derive_h(hash);
        return self.b[h1 as usize] ^ self.b[h2 as usize] ^ self.b[h3 as usize] == fingerprint;
    }
}

#[cfg(test)]
mod tests {
    use super::XorFilter;
    #[test]
    fn construct_filter() {
        let elements = vec![1, 2, 4, 6];
        let xor_filter = XorFilter::<i32>::new(elements.len(), &elements);
        assert!(xor_filter.contains(&1));
        assert!(xor_filter.contains(&2));
        assert!(xor_filter.contains(&4));
        assert!(xor_filter.contains(&6));
    }
}
