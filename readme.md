go implementation of @openzeppelin/merkle-tree

This library works on "standard" merkle trees designed for Ethereum smart contracts. We have defined them with a few characteristics that make them secure and good for on-chain verification.

The tree is shaped as a complete binary tree.
The leaves are sorted.
The leaves are the result of ABI encoding a series of values.
The hash used is Keccak256.

# API 


