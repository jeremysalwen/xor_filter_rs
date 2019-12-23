use len_trait::Len;
use linked_hash_set::LinkedHashSet;
use num::Zero;
use std::collections::hash_map::RandomState;
use std::fmt::Debug;
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
    BitXor<Self, Output = Self> + BitXorAssign<Self> + PartialEq + Copy + Zero + Debug
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
        .filter_map(|(i, &c)| if c == 1 { Some(i + start) } else { None })
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

    if occupancy_counts[index as usize] == 1 && queue.insert_if_absent(index as usize) {
        println!("Not removing! {}", index);
    } else {
        println!("removing! {}", index);
        queue.remove(&(index as usize));
    }
}

fn pop_queues<T: Eq + Hash + Copy>(
    queue1: &mut LinkedHashSet<T>,
    queue2: &mut LinkedHashSet<T>,
    queue3: &mut LinkedHashSet<T>,
) -> Option<T> {
    queue1
        .front()
        .or_else(|| queue2.front().or_else(|| queue3.front()))
        .map(|&x| x)
}

// Note that this returns a value which is 1/3
// the value "c" used in the paper
fn table_size(num_elements: usize) -> usize {
    // (1.23 * num_elements + 32)/3
    (num_elements * 41 + 1067) / 100
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
    // code, since I don't trust myself to implement fast and unbiased
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

    pub fn new<'a, I>(elements: &'a I) -> Self
    where
        &'a I: IntoIterator<Item = &'a T>,
        I: Len,
        T: 'a,
    {
        // According to the paper, each try has a >80% chance of success.
        // Retrying 17 times puts the probability of failure at 1e-12.
        // Much more likely, this will occur due to a bad hash function H,
        // either due to bias causing collisions to be more likely than
        // chance, or due to 64 bit hashes being too small (>2^32 elements).
        Self::new_with_max_tries(elements, 17).expect(
            "XorFilter construction repeatedly failed.  Likely due to an inadequate hash function.",
        )
    }

    pub fn new_with_max_tries<'a, I>(elements: &'a I, max_tries: usize) -> Option<Self>
    where
        &'a I: IntoIterator<Item = &'a T>,
        I: Len,
        T: 'a,
    {
        // Size the table according to the number of elements
        let size = table_size(elements.len());
        let c: usize = (size * 3) as usize;
        let mut filter = Self {
            size: size as u64,
            b: vec![F::zero(); c],
            hash_builder: H::default(),
            _phantomt: PhantomData {},
        };
        for _ in 0..max_tries {
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

            println!("{:?} {:?} {:?}", occupancy_codes, occupancy_counts, stack);

            while let Some(index) = pop_queues(&mut queue1, &mut queue2, &mut queue3) {
                println!("{} {:?} {:?} {:?}", index, queue1, queue2, queue3);

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
            println!("{:?} {:?} {:?}", occupancy_codes, occupancy_counts, stack);

            if num_elements == stack.len() {
                // Success!
                for &(i, hash) in stack.iter().rev() {
                    let (h1, h2, h3) = filter.derive_h(hash);
                    println!(
                        "h {:?} {} {} {}",
                        XorFilter::<T, F, H>::derive_fingerprint(hash),
                        h1,
                        h2,
                        h3
                    );
                    filter.b[i] = F::zero();
                    filter.b[i] = XorFilter::<T, F, H>::derive_fingerprint(hash)
                        ^ filter.b[h1 as usize]
                        ^ filter.b[h2 as usize]
                        ^ filter.b[h3 as usize];
                }
                println!("filter {:?}", filter.b);
                return Some(filter);
            } else {
                // Try again with another hasher.
                filter.hash_builder = H::default();

                stack.clear();
            }
        }
        return None;
    }

    pub fn contains(&self, value: &T) -> bool {
        let hash = self.hash(value);
        let fingerprint = Self::derive_fingerprint(hash);
        let (h1, h2, h3) = self.derive_h(hash);

        println!("hashcontains {:?} {} {} {}", fingerprint, h1, h2, h3);

        println!(
            "hashentries {:?} {:?} {:?} {:?}",
            fingerprint, self.b[h1 as usize], self.b[h2 as usize], self.b[h3 as usize]
        );
        let x = self.b[h1 as usize] ^ self.b[h2 as usize] ^ self.b[h3 as usize] == fingerprint;
        println!("x {}", x);
        return x;
    }
}

#[cfg(test)]
mod tests {
    use super::XorFilter;
    use std::hash::Hash;
    use std::fmt::Debug;

    fn test_construction<T:Hash+Debug>(elements:Vec<T>, negatives:Vec<T>) {
        let xor_filter = XorFilter::<T>::new(&elements);
        for element in elements.iter() {
            assert!(xor_filter.contains(element));
        }
        for element in negatives.iter() {
            println!("negative {:?}", element);
            assert!(!xor_filter.contains(element));
        }
    }
    #[test]
    fn randos() {
        test_construction(vec![6,23523,43,8,345],vec![1,586,5,34,7]);
    }
    #[test]
    fn no_entry() {
        let elements: Vec<i32> = vec![0; 0];
        let xor_filter = XorFilter::<i32>::new(&elements);
        assert!(!xor_filter.contains(&1));
    }
    #[test]
    fn one_entry() {
        let elements = vec![11];
        let xor_filter = XorFilter::<i32>::new(&elements);
        assert!(xor_filter.contains(&11));
        assert!(!xor_filter.contains(&16));
    }
    #[test]
    fn construct_filter() {
        let elements = vec![1, 2, 4, 6];
        let xor_filter = XorFilter::<i32>::new(&elements);
        assert!(xor_filter.contains(&1));
        assert!(xor_filter.contains(&2));
        assert!(xor_filter.contains(&4));
        assert!(xor_filter.contains(&6));
    }
}
