package merkle_tree

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"testing"
)

func generateLeaves(num int) []Node {
	leaves := make([]Node, num)

	for i := 0; i < num; i++ {
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write([]byte(fmt.Sprint(i)))
		leaves[i] = hasher.Sum(nil)
	}
	return leaves
}

func TestSiblingIndex(t *testing.T) {
	sib, err := siblingIndex(0)
	require.Error(t, err)

	sib, err = siblingIndex(1)
	require.NoError(t, err)
	require.Equal(t, 2, sib)

	sib, err = siblingIndex(2)
	require.NoError(t, err)
	require.Equal(t, 1, sib)

	sib, err = siblingIndex(3)
	require.NoError(t, err)
	require.Equal(t, 4, sib)

	sib, err = siblingIndex(4)
	require.NoError(t, err)
	require.Equal(t, 3, sib)

	sib, err = siblingIndex(5)
	require.NoError(t, err)
	require.Equal(t, 6, sib)

	sib, err = siblingIndex(6)
	require.NoError(t, err)
	require.Equal(t, 5, sib)

	sib, err = siblingIndex(7)
	require.NoError(t, err)
	require.Equal(t, 8, sib)

	sib, err = siblingIndex(13)
	require.NoError(t, err)
	require.Equal(t, 14, sib)
}

func TestParentIndex(t *testing.T) {
	parent, err := parentIndex(0)
	require.Error(t, err)

	parent, err = parentIndex(1)
	require.NoError(t, err)
	require.Equal(t, 0, parent)

	parent, err = parentIndex(2)
	require.NoError(t, err)
	require.Equal(t, 0, parent)

	parent, err = parentIndex(3)
	require.NoError(t, err)
	require.Equal(t, 1, parent)

	parent, err = parentIndex(4)
	require.NoError(t, err)
	require.Equal(t, 1, parent)

	parent, err = parentIndex(5)
	require.NoError(t, err)
	require.Equal(t, 2, parent)

	parent, err = parentIndex(6)
	require.NoError(t, err)
	require.Equal(t, 2, parent)

	parent, err = parentIndex(7)
	require.NoError(t, err)
	require.Equal(t, 3, parent)

	parent, err = parentIndex(13)
	require.NoError(t, err)
	require.Equal(t, 6, parent)
}

//0:044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d
//1:c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6
//2:ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5
//3:2a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de
func TestHasher(t *testing.T) {
	for i := 0; i < 4; i++ {
		msg := []byte(fmt.Sprint(i))

		//eth keccak256
		h1 := crypto.Keccak256(msg)

		//sha3.keccak256
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(msg)
		h2 := hasher.Sum(nil)

		require.Equal(t, h1, h2)
	}
}

func TestNewMerkleTree(t *testing.T) {
	leaves := generateLeaves(4)
	tree, err := NewMerkeTree(sha3.NewLegacyKeccak256(), leaves)
	require.NoError(t, err)

	proof, err := tree.GetProofByIndex(3)
	require.NoError(t, err)

	root, err := tree.ProcessProof(tree.Nodes[3], proof)
	require.NoError(t, err)
	require.Equal(t, root, tree.Nodes[0])

	root, err = tree.ProcessProof(leaves[0], proof)
	require.NoError(t, err)
	require.Equal(t, root, tree.Nodes[0])
}

func TestNewMerkleTree_EmptyLeaves(t *testing.T) {
	_, err := NewMerkeTree(sha3.NewLegacyKeccak256(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mpty leaves")
}

func TestGetProof(t *testing.T) {
	leaves := generateLeaves(16)
	tree, err := NewMerkeTree(sha3.NewLegacyKeccak256(), leaves)
	require.NoError(t, err)

	for i := 0; i < len(leaves); i++ {
		leaf := leaves[i]
		proof, err := tree.GetProof(leaf)
		require.NoError(t, err)
		fmt.Printf("i:%v,leaf:%x,\nproof:%x,\nroot:%x\n", i, leaf, proof, tree.Nodes[0])
		fmt.Printf("\n")

		root, err := tree.ProcessProof(leaf, proof)
		require.NoError(t, err)
		require.Equal(t, root, tree.Nodes[0])
	}
}

func TestHashPair(t *testing.T) {
	a, err := hex.DecodeString("044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d")
	require.NoError(t, err)
	b, err := hex.DecodeString("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6")
	require.NoError(t, err)

	tree := Tree{
		Hasher: sha3.NewLegacyKeccak256(),
	}
	h1 := tree.hashPair(a, b)
	h2 := tree.hashPair(b, a)
	require.Equal(t, h1, h2)
}

func TestVerify(t *testing.T) {
	leaves := generateLeaves(4)
	tree, err := NewMerkeTree(sha3.NewLegacyKeccak256(), leaves)
	require.NoError(t, err)

	require.True(t, tree.Verify())

	tree = &Tree{}
	require.False(t, tree.Verify())

	tree = &Tree{
		Nodes: []Node{leaves[0], leaves[1]},
	}
	require.False(t, tree.Verify())

	tree = &Tree{
		Hasher: sha3.NewLegacyKeccak256(),
		Nodes:  []Node{leaves[0], leaves[1], leaves[2]},
	}
	require.False(t, tree.Verify())
}

func TestView(t *testing.T) {
	leaves := generateLeaves(16)
	tree, err := NewMerkeTree(sha3.NewLegacyKeccak256(), leaves)
	require.NoError(t, err)
	tree.View()
}

func TestDump(t *testing.T) {
	leaves := generateLeaves(16)
	tree, err := NewMerkeTree(sha3.NewLegacyKeccak256(), leaves)
	require.NoError(t, err)
	fmt.Println(tree.Dump())
}
