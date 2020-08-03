// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module provides an implementation of the Xor Filter,
//! as described in
//!
//! Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters
//! THOMAS MUELLER GRAF and DANIEL LEMIRE,University of Quebec (TELUQ), Canada
//!
//! As thae title of the paper suggests, they are an approximate
//! set membership datastructure that is faster and smaller than Bloom
//! Filters and Cuckoo Filters. The only downside is that they are
//! immutable once constructed.
//!
//! This implementation has been unit tested, but still needs to be
//! subjected to a battery of statistical tests. Performance has also
//! not been rigorously measured.
#![warn(missing_docs)]

#[cfg(any(test, fuzzing))]
extern crate more_asserts;
#[cfg(any(test, fuzzing))]
extern crate statrs;

use linked_hash_set::LinkedHashSet;
use num::Bounded;
use num::Zero;
use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::BuildHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::marker::PhantomData;
use std::ops::BitXor;
use std::ops::BitXorAssign;

/// An XorFilter is an approximate set membership datastructure.
/// Like bloom filters, they have no false negatives, but a small
/// chance of false positives.
///
/// The false positive rate is 1/2^N where N is the bit width of
/// `F`.  for `F=u8`, the probability is 1/256, for `F=u16` it is
/// 1/65536 (Since XorFilter derives 3 `F` values from a single hash,
/// FingerprintTypes of width greater than 16 don't make sense with
/// the current implementation.)
pub struct XorFilter<T: Hash, F: FingerprintType = u16, H: BuildHasher = RandomState> {
    size: u64, // Note this is 1/3 the length of B, i.e. c/3 in the original paper.
    b: Vec<F>,
    hash_builder: H,
    _phantomt: PhantomData<T>,
}
// Reduces a random u64 to the interval [0, range), where
// `range` is not neessarily a power of two.  This is described
// in the XorFilter, which references
// Daniel Lemire. 2019. Fast Random Integer Generation in an Interval.ACM Trans. Model. Comput. Simul.29, 1, Article 3(Jan. 2019), 12 pages
fn fast_random_integer_reduce(x: u64, range: u64) -> u64 {
    (((x as u128) * (range as u128)) >> 64) as u64
}

/// Trait for types which can be used as the hash type
/// for the XorFilter.  Currently only implemented for
/// u8 and u16, as was done in the original paper.  Since
/// all three hash values are derived from a single 64 bit
/// hash value, widths greater than 16 do not make sense
/// with the current implementation.  If base hash width is
/// expanded in the future, then this could reasonably be
/// expanded to larger bit widths.
pub trait FingerprintType:
    BitXor<Self, Output = Self>
    + BitXorAssign<Self>
    + Into<u64>
    + Bounded
    + PartialEq
    + Copy
    + Zero
    + Debug
{
    /// Derives a fingerprint from a source u64
    /// hash value.
    fn from(x: u64) -> Self;

    /// Returns the inverse probability of a false positive,
    /// when using this FingerrintType in an XorFilter.
    fn inverse_false_positive_prob() -> u64 {
        Self::max_value().into() - Self::min_value().into()
    }
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

/// Data structure for keeping track of sets of elements at each index,
/// used when constructing a XorFilter.
///
/// It stores a count for each index, along with the XOR of the hashes of
/// all elements in the bucket.  This way elements can be added or removed,
/// and if there is a single element in the bucket, its hash can be read.
struct OccupancyTable {
    codes: Vec<u64>,
    counts: Vec<u64>,
}

impl OccupancyTable {
    fn new(size: usize) -> Self {
        Self {
            codes: vec![0; size],
            counts: vec![0; size],
        }
    }
    fn clear(&mut self) {
        let len = self.codes.len();
        self.codes.clear();
        self.counts.clear();
        self.codes.resize(len, 0);
        self.counts.resize(len, 0);
    }

    fn insert(&mut self, index: usize, hash: u64) {
        self.codes[index] ^= hash;
        self.counts[index] += 1;
    }
    /// Helper function that removes an element at a given index from the occupancy
    /// table, and adds it to the queue if it was not already in the queue.  If it
    /// was already in the queue, then it instead removes it.
    fn remove(&mut self, hash: u64, index: usize, queue: &mut LinkedHashSet<usize>) {
        self.codes[index as usize] ^= hash;
        self.counts[index as usize] -= 1;

        if self.counts[index as usize] != 1 || !queue.insert_if_absent(index as usize) {
            queue.remove(&(index as usize));
        }
    }
    // Returns the set of indices between two bounds which contain exactly one element.
    fn single_element_indices(&self, start: usize, end: usize) -> LinkedHashSet<usize> {
        self.counts[start..end]
            .iter()
            .enumerate()
            .filter_map(|(i, &c)| if c == 1 { Some(i + start) } else { None })
            .collect()
    }
    // Returns the XOR of all the hashes of the elements stored in a given bucket.
    // If the bucket contains just one element, this will just be the hash of that
    // element.
    fn get(&self, index: usize) -> u64 {
        self.codes[index]
    }
}

// Helper function that returns the front of element of three queues,
// with priority given to queue1, then queue2, then queue3.
fn queues_front<T: Eq + Hash + Copy>(
    queue1: &LinkedHashSet<T>,
    queue2: &LinkedHashSet<T>,
    queue3: &LinkedHashSet<T>,
) -> Option<T> {
    queue1
        .front()
        .or_else(|| queue2.front().or_else(|| queue3.front()))
        .map(|&x| x)
}

/// Calculates the appropriate table size based on
/// number of elements to be inserted.
/// Note that this returns a value which is 1/3
/// the value "c" used in the paper.
fn table_size(num_elements: usize) -> usize {
    // (1.23 * num_elements + 32)/3
    (num_elements * 41 + 1067) / 100
}

impl<T: Hash, F: FingerprintType, H: BuildHasher> XorFilter<T, F, H> {
    /// Hashes an element with this XorFilter's hasher.
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

    /// Checks whether this XorFilter contains the given element.
    /// If it does, this function will always return true.  If
    /// it does not, there is some probability of false positive.
    pub fn contains(&self, value: &T) -> bool {
        let hash = self.hash(value);
        let fingerprint = Self::derive_fingerprint(hash);
        let (h1, h2, h3) = self.derive_h(hash);
        return self.b[h1 as usize] ^ self.b[h2 as usize] ^ self.b[h3 as usize] == fingerprint;
    }

    /// Helper function which does the meat of building the XorFilter.  It expects the filter to have
    /// the size and hash_builder initialized, but not the array `b`. The occupancy_table and stack are
    /// expected to be cleared.
    fn try_build<'a, I>(
        filter: &mut Self,
        occupancy_table: &mut OccupancyTable,
        stack: &mut Vec<(usize, u64)>,
        elements: I,
    ) -> bool
    where
        I: ExactSizeIterator<Item = &'a T> + Clone,
        T: 'a,
    {
        // First we calculate the occupancy code (xor of all hashes) and occupancy count
        for element in elements.clone() {
            let hash = filter.hash(element);
            let (h1, h2, h3) = filter.derive_h(hash);

            let occupancy_code = hash;
            occupancy_table.insert(h1 as usize, occupancy_code);
            occupancy_table.insert(h2 as usize, occupancy_code);
            occupancy_table.insert(h3 as usize, occupancy_code);
        }
        // Then we construct the queues of indices in the occupancy table with only a single element.
        let mut queue1: LinkedHashSet<usize> =
            occupancy_table.single_element_indices(0, filter.size as usize);
        let mut queue2: LinkedHashSet<usize> = occupancy_table
            .single_element_indices(1 * filter.size as usize, 2 * filter.size as usize);
        let mut queue3: LinkedHashSet<usize> = occupancy_table
            .single_element_indices(2 * filter.size as usize, 3 * filter.size as usize);

        // Finally we work through the queues, adding new entries as we find them, and adding the
        // processed elements to the stack.
        while let Some(index) = queues_front(&mut queue1, &mut queue2, &mut queue3) {
            let hash = occupancy_table.get(index);
            let (h1, h2, h3) = filter.derive_h(hash);
            occupancy_table.remove(hash, h1 as usize, &mut queue1);
            occupancy_table.remove(hash, h2 as usize, &mut queue2);
            occupancy_table.remove(hash, h3 as usize, &mut queue3);
            stack.push((index, hash));
        }

        // This means we processed every index in the occupancy table with only a single element,
        // but there are still elements we missed.  Thus the attempt has failed, and we would
        // need to try again with a different hasher.
        if elements.len() != stack.len() {
            return false;
        }
        // Finally, construct the entries of the table based on the stack.
        for &(i, hash) in stack.iter().rev() {
            let (h1, h2, h3) = filter.derive_h(hash);
            filter.b[i] = F::zero();
            filter.b[i] = XorFilter::<T, F, H>::derive_fingerprint(hash)
                ^ filter.b[h1 as usize]
                ^ filter.b[h2 as usize]
                ^ filter.b[h3 as usize];
        }
        return true;
    }

    /// Constructs a new XorFilter given a set of unique elements, and a specified HashBuilder
    /// to use.  This is guaranteed to succeed in constructing an XorFilter at least 80% of the
    /// time (according to the original paper).  If it does not succeed, you can try again with
    /// another HashBuilder.
    ///
    /// Note that if the elements are not unique, this will always fail.
    pub fn new_from_unique_with_hasher<'a, I>(elements: I, hash_builder: H) -> Option<Self>
    where
        I: ExactSizeIterator<Item = &'a T> + Clone,
        T: 'a,
    {
        // Size the table according to the number of elements
        let num_elements = elements.len();
        let size = table_size(num_elements);
        let c: usize = (size * 3) as usize;
        let mut filter = Self {
            size: size as u64,
            b: vec![F::zero(); c],
            hash_builder: hash_builder,
            _phantomt: PhantomData {},
        };
        let mut occupancy_table = OccupancyTable::new(c);
        let mut stack = Vec::<(usize, u64)>::with_capacity(num_elements);
        if Self::try_build(&mut filter, &mut occupancy_table, &mut stack, elements) {
            return Some(filter);
        } else {
            return None;
        }
    }
}

impl<T: Hash, F: FingerprintType, H: BuildHasher + Default> XorFilter<T, F, H> {
    /// Creates a new XorFilter from a set of unique elements.
    ///
    /// Assuming the HashBuilder H is unbiased, and there are no duplicate elements,
    /// it will only fail (and panic) with probability <1e-12.  If there are duplicate
    /// elements, it will always panic, and if the hash functions are biased, it may
    /// randomly fail with higher probability than 1e-12.
    ///
    /// If your elements are not guaranteed to be unique, you can instead use
    /// XorFilter::new(), which uses a HashSet to uniquify the elements before construction.
    pub fn new_from_unique<'a, I>(elements: I) -> Self
    where
        I: ExactSizeIterator<Item = &'a T> + Clone,
        T: 'a,
    {
        // According to the paper, each try has a >80% chance of success.
        // Retrying 17 times puts the probability of failure at 1e-12.
        // Much more likely, this will occur due to a bad hash function H,
        // either due to bias causing collisions to be more likely than
        // chance, or due to 64 bit hashes being too small (>2^32 elements).
        Self::new_from_unique_with_max_tries(elements, 17).expect(
            "XorFilter construction repeatedly failed.  Likely due to duplicate elements or an inadequate hash function.",
        )
    }

    /// Creates a new XorFilter from a set of unique elements.
    ///
    /// The construction will be attempted up to `max_tries` times before giving up.
    ///
    /// Assuming your hashes are random and independent, the probability of success
    /// for each attempt will be >80%, and independent.
    ///
    /// If your elements are not guaranteed to be unique, you can instead use
    /// XorFilter::new_with_max_tries(), which uses a HashSet to uniquify the elements
    /// before construction.
    pub fn new_from_unique_with_max_tries<'a, I>(elements: I, max_tries: usize) -> Option<Self>
    where
        I: ExactSizeIterator<Item = &'a T> + Clone,
        T: 'a,
    {
        // Size the table according to the number of elements
        let num_elements = elements.len();
        let size = table_size(num_elements);
        let c: usize = (size * 3) as usize;
        let mut filter = Self {
            size: size as u64,
            b: vec![F::zero(); c],
            hash_builder: H::default(),
            _phantomt: PhantomData {},
        };
        let mut occupancy_table = OccupancyTable::new(c);
        let mut stack = Vec::<(usize, u64)>::with_capacity(num_elements);

        for _ in 0..max_tries {
            if Self::try_build(
                &mut filter,
                &mut occupancy_table,
                &mut stack,
                elements.clone(),
            ) {
                return Some(filter);
            } else {
                // Try again with another hasher.
                filter.hash_builder = H::default();
                occupancy_table.clear();
                stack.clear();
            }
        }
        return None;
    }
}

impl<T: Hash + Eq, F: FingerprintType, H: BuildHasher + Default> XorFilter<T, F, H> {
    /// Creates a new XorFilter from a set of elements.
    ///
    /// Assuming the default HashBuilder H is unbiased, and there are no duplicate elements,
    /// it will only fail (and panic) with probability <1e-12. If the hash functions
    /// are biased, the probability may be higher than 1e-12.
    ///
    /// The elements do not need to be unique. If your elements are guaranteed to be
    /// unique, you can instead use XorFilter::new_from_unique(), which saves the
    /// construction of a temporary HashSet internally.
    pub fn new<'a, I>(elements: I) -> Self
    where
        I: ExactSizeIterator<Item = &'a T> + Clone,
        T: 'a,
    {
        let set: HashSet<&T> = elements.clone().collect();

        if set.len() == elements.len() {
            return XorFilter::<T, F, H>::new_from_unique(elements);
        }
        return XorFilter::<T, F, H>::new_from_unique(set.iter().copied());
    }

    /// Creates a new XorFilter from a set of elements.
    ///
    /// The construction will be attempted up to `max_tries` times before giving up.
    ///
    /// Assuming your hashes are random and independent, the probability of success
    /// for each attempt will be >80%, and independent.
    ///
    /// The elements do not need to be unique. If your elements are guaranteed to be
    /// unique, you can instead use XorFilter::new_from_unique(), which saves the
    /// construction of a temporary HashSet internally.
    pub fn new_with_max_tries<'a, I>(elements: I, max_tries: usize) -> Option<Self>
    where
        I: ExactSizeIterator<Item = &'a T> + Clone,
        T: 'a,
    {
        let set: HashSet<&T> = elements.clone().collect();

        if set.len() == elements.len() {
            return XorFilter::<T, F, H>::new_from_unique_with_max_tries(elements, max_tries);
        }
        return XorFilter::<T, F, H>::new_from_unique_with_max_tries(
            set.iter().copied(),
            max_tries,
        );
    }
}

/// Internal testing utilities for XorFilter.  Only public because Cargo Fuzz requires it.
pub mod test_util {
    /// Internal testing utility function.
    pub fn test_construction<T: std::hash::Hash + Eq + std::fmt::Debug>(
        elements: &Vec<T>,
        negatives: &Vec<T>,
    ) {
        let xor_filter = super::XorFilter::<T>::new(elements.iter());
        for element in elements.iter() {
            assert!(xor_filter.contains(element));
        }
        for element in negatives.iter() {
            assert!(!xor_filter.contains(element));
        }
    }
}

/// Note that all of these tests might fail occasionally, since they are probabilistic.
/// Proper, rigorous testing of the statistical properties of this implementation is
/// still required.
#[cfg(test)]
pub mod tests {

    #[test]
    fn randos() {
        super::test_util::test_construction(&vec![6, 23523, 43, 8, 345], &vec![1, 586, 5, 34, 7]);
    }

    #[test]
    fn no_entry() {
        super::test_util::test_construction(&vec![], &vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }
    #[test]
    fn one_entry() {
        super::test_util::test_construction(&vec![11], &vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }
    #[test]
    fn multiple_elements() {
        super::test_util::test_construction(&vec![1, 2, 4, 6], &vec![3, 5, 7, 8, 9, 10]);
    }

    #[test]
    fn strings() {
        super::test_util::test_construction(
            &vec!["dog", "cat", "elephant", "sheep"],
            &vec!["cow", "hippo", "owl", "whale"],
        );
    }

    #[cfg(any(test, fuzzing))]
    pub mod statistical {

        use statrs::function::erf::erf_inv;
        use more_asserts::assert_lt;
        use bolero::check;
        
        /// Returns the required sample size for a one-sided binomial test with
        /// specified false positive and false negative rates.
        ///
        /// Uses the normal approximation of the binomial with the continuity
        /// correction, and so is not exact, especially for small n
        pub fn normal_approx_sample_size(
            p0: f64,
            p1: f64,
            false_positive_rate: f64,
            false_negative_rate: f64,
        ) -> (u64, u64) {
            let b0 = (2.0 * p0 * (1.0 - p0)).sqrt() * erf_inv(2.0 * false_positive_rate - 1.0);
            let b1 = (2.0 * p1 * (1.0 - p1)).sqrt() * erf_inv(2.0 * false_negative_rate - 1.0);
            let b = b0 + b1;
            let n = (b / (p1 - p0)).powi(2).ceil();
            let k = (-n.sqrt() * b0 + 0.5 + n * p0).round();
            let k2 = n.sqrt() * b1 + 0.5 + n * p1;
            println!("{} {} {} {}", p0, p1, false_positive_rate, false_negative_rate);
            println!("OK n {} k0 {} k1 {}", n, k, k2);
            return (n as u64, k as u64);
        }

        fn required_sample_size(
            p0: f64,
            p1: f64,
            false_positive_rate: f64,
            false_negative_rate: f64,
        ) -> (u64, u64) {
            let (mut n, mut k) =
                normal_approx_sample_size(p0, p1, false_positive_rate, false_negative_rate);
            //if check(n,k,p0,p1, false_positive_rate, false_negative_rate) {
            //    return (n,k);
            //}
            return (n, k);
        }

        /// Checks the sanity of the output of the normal approximation.
        ///
        /// This checks that the power and p-value of for the normal approximation
        /// of the binomial satisfy the false_positive and false_negative
        /// constraints required.  This must hold true, because solving these
        /// constraints on the normal approximation is the basis for the sample
        /// size calculation algorithm.
        fn assert_normal_approx_satisfied(
            n: u64,
            k: u64,
            p0: f64,
            p1: f64,
            false_positive_rate: f64,
            false_negative_rate: f64,
        ) {
            let nf = n as f64;
            // We add a margin of 0.5, due to potential rounding.
            let k0 = k as f64 + 0.5;
            let k1 = k as f64 - 0.5;
            let approx_false_positive = 0.5
                * (1.0
                    + statrs::function::erf::erf(
                        (0.5 - k0 + nf * p0) / (2.0 * nf * p0 * (1.0 - p0)).sqrt(),
                    ));
            let approx_false_negative = 0.5
                * (1.0
                    + statrs::function::erf::erf(
                        (-0.5 + k1 - nf * p1) / (2.0 * nf * p1 * (1.0 - p1)).sqrt(),
                    ));
            println!(
                "n {} k {} approx fp {} approx fn {}",
                n, k, approx_false_positive, approx_false_negative
            );
            assert_lt!(approx_false_positive, false_positive_rate);
            assert_lt!(approx_false_negative, false_negative_rate);
        }

        #[test]
        fn test_normal_approx_sample_size() {
            let p0 = 0.1;
            let p1 = 0.15;
            let false_positive_rate = 0.05;
            let false_negative_rate = 0.05;
            let (n, k) =
                normal_approx_sample_size(p0, p1, false_positive_rate, false_negative_rate);
            assert_normal_approx_satisfied(n, k, p0, p1, false_positive_rate, false_negative_rate);
            assert_eq!((n, k), (468, 58));
        }

        #[test]
        fn normal_approx_property_test() {
                check!(for (mut p0,mut p1, fpr, fnr) in all((gen::<f64>(), gen::<f64>(), gen::<f64>().with()
                .bounds(0..1.0), gen::<f64>())) {
                // Make sure p1 is bigger.
                if p1<p0 {
                    std::mem::swap(&mut p0, &mut p1);
                }
                let (n, k) =
                normal_approx_sample_size(p0, p1, fpr, fnr);
                assert_normal_approx_satisfied(n, k, p0, p1, fpr, fnr);
            });
        }
    }
}
