package merkle_tree

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math"
)

const DigestLength = 32

type Node []byte

type Tree struct {
	Hasher hash.Hash
	Nodes  []Node
}

func (tree *Tree) hashPair(a Node, b Node) []byte {
	tree.Hasher.Reset()
	buff := bytes.Buffer{}
	if bytes.Compare(a[:], b[:]) != 1 {
		buff.Write(a[:])
		buff.Write(b[:])
	} else {
		buff.Write(b[:])
		buff.Write(a[:])
	}
	tree.Hasher.Write(buff.Bytes())
	return tree.Hasher.Sum(nil)
}

func leftChildIndex(i int) int {
	return 2*i + 1
}

func rightChildIndex(i int) int {
	return 2*i + 2
}

func parentIndex(i int) (int, error) {
	if i == 0 {
		return 0, errors.New("root has no parent")
	}

	return int(math.Floor((float64(i) - 1) / 2)), nil
}

func siblingIndex(i int) (int, error) {
	if i == 0 {
		return 0, errors.New("root has no siblings")
	}

	if i%2 == 0 {
		return i - 1, nil
	} else {
		return i + 1, nil
	}
}

func isTreeNode(tree *Tree, i int) bool {
	return i >= 0 && i < len(tree.Nodes)
}

func isInternalNode(tree *Tree, i int) bool {
	return isTreeNode(tree, leftChildIndex(i))
}

func isLeafNode(tree *Tree, i int) bool {
	return isTreeNode(tree, i) && !isInternalNode(tree, i)
}

func isValidMerkleNode(node Node) bool {
	return len([]byte(node)) == DigestLength
}

func isPowerOf2(num int) bool {
	return num&(num-1) == 0
}

//NewMerkeTree build a merkle tree
//@hasher hash algorithm
//@leaves leaves
func NewMerkeTree(hasher hash.Hash, leaves []Node) (*Tree, error) {
	leavesLength := len(leaves)
	if leavesLength == 0 {
		return nil, errors.New("empty leaves")
	}

	if !isPowerOf2(len(leaves)) {
		return nil, errors.New("only support complete binary tree")
	}

	for i := 0; i < leavesLength; i++ {
		if !isValidMerkleNode(leaves[i]) {
			return nil, errors.New("node's byte length is not 32")
		}
	}

	if hasher == nil {
		return nil, errors.New("no hasher")
	}

	tree := &Tree{
		Hasher: hasher,
		Nodes:  make([]Node, 2*leavesLength-1),
	}

	for i, leaf := range leaves {
		tree.Nodes[leavesLength-1+i] = leaf
	}

	for i := leavesLength - 2; i >= 0; i-- {
		tree.Nodes[i] = tree.hashPair(tree.Nodes[leftChildIndex(i)], tree.Nodes[rightChildIndex(i)])
	}

	return tree, nil
}

//GetProofByIndex get the proof
//@i leaf's index
func (tree *Tree) GetProofByIndex(i int) ([]Node, error) {
	if !isLeafNode(tree, i) {
		return nil, errors.New("not a leaf node")
	}

	proof := make([]Node, 0)
	for i > 0 {
		sibIndex, _ := siblingIndex(i)
		proof = append(proof, tree.Nodes[sibIndex])
		i, _ = parentIndex(i)
	}
	return proof, nil
}

//GetProof get the proof
//@leaf leaf's content
func (tree *Tree) GetProof(leaf Node) ([]Node, error) {
	leafBeginIndex := len(tree.Nodes) / 2

	found := false
	i := leafBeginIndex
	for ; i < len(tree.Nodes); i++ {
		if bytes.Compare(leaf, tree.Nodes[i]) == 0 {
			found = true
			break
		}
	}

	if !found {
		return nil, errors.New("not a leaf node")
	}

	return tree.GetProofByIndex(i)
}

//ProcessProof build the root
//@leaf leaf
//@proof proof
func (tree *Tree) ProcessProof(leaf Node, proof []Node) (Node, error) {
	if !isValidMerkleNode(leaf) {
		return nil, errors.New("not a merkle node ")
	}

	for i := 0; i < len(proof); i++ {
		if !isValidMerkleNode(proof[i]) {
			return nil, errors.New("not a merkle node ")
		}
	}

	node := leaf
	for i := 0; i < len(proof); i++ {
		node = tree.hashPair(node, proof[i])
	}

	return node, nil
}

//Verify verify the tree is valid or not
func (tree *Tree) Verify() bool {
	return isValidMerkleTree(tree)
}

func (tree *Tree) Dump() string {
	if !tree.Verify() {
		return ""
	}
	buff := bytes.Buffer{}
	for i := 0; i < len(tree.Nodes); i++ {
		buff.WriteString(fmt.Sprintf("0x%x,", tree.Nodes[i]))
	}
	str := buff.String()
	str = str[:len(str)-1]
	return str
}

func (tree *Tree) View() {
	if !tree.Verify() {
		return
	}

	height := int(math.Log2(float64(len(tree.Nodes) + 1)))
	for i := 0; i < height; i++ {
		begin := int(math.Pow(float64(2), float64(i))) - 1
		end := int(math.Pow(float64(2), float64(i+1))) - 1
		for j := begin; j < end; j++ {
			fmt.Printf("[0x%x] ", tree.Nodes[j])
		}
		fmt.Printf("\n")
	}
}

//isValidMerkleTree
//@tree a merkle tree
func isValidMerkleTree(tree *Tree) bool {
	treeLength := len(tree.Nodes)
	if !isPowerOf2(treeLength + 1) {
		return false
	}

	for i, node := range tree.Nodes {
		if !isValidMerkleNode(node) {
			return false
		}

		l := leftChildIndex(i)
		r := rightChildIndex(i)

		if r >= treeLength {
			if l < treeLength {
				return false
			}
		} else if bytes.Compare(node, tree.hashPair(tree.Nodes[l], tree.Nodes[r])) != 0 {
			return false
		}
	}
	return treeLength > 0
}
