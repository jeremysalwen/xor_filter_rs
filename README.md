# XorFilter

This is an implmentation of an Xor Filter, a probabilistic set membership data structure.

It is like a bloom filter, but faster and smaller, and immutable. See the original paper
for all the details:
```
@misc{graf2019xor,
    title={Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters},
    author={Thomas Mueller Graf and Daniel Lemire},
    year={2019},
    eprint={1912.08258},
    archivePrefix={arXiv},
    primaryClass={cs.DS}
}
```

This is not an officially supported Google product.

## Usage

Add this to your `Cargo.toml`:
```toml
[dependencies]
xor_filter = "*"
```
and this to your crate root:
```rust
extern crate xor_filter;
```

## License

`xor_filter` is licensed under the terms of the Apache
License (Version 2.0).

See [LICENSE](LICENSE) for more details.
