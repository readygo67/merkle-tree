go implementation of @openzeppelin/merkle-tree's core.ts 

This library works on "standard" merkle trees designed for Ethereum smart contracts. We have defined them with a few characteristics that make them secure and good for on-chain verification.
The tree is shaped as a complete binary tree,i.e. the leaves number must be 2^n.
The leaves are sorted.
The leaves are the result of ABI encoding a series of values.
The hash used is Keccak256.

the online merkle verifier is @ https://testnet.bscscan.com/address/0x0d62a93bbc501109d2d968d9e4ab2f373f3383b2








