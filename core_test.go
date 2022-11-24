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

//[0xe0f5d02b94992e2c9aa984558366eb83433af4fae7c9363e36df3c379d5813a0]
//[0x148a4bddd7fd0bdb7a7039921c7e103f17e6935a5b33f281d82f05a2fde848d3] [0x90438c7fd0c8751e4c0f3f8c0f70e3a74cc6b4dcc3214528df2d70e5b9e8b795]
//[0xaa9e8275107be9f8089f326bcaaa568367efd2d253eed8cc411711f371c7caeb] [0x3235290a71c29b8c01eeb9f16e5cce045aa813fcef791814806e2ff11feb519f] [0xb6debd119c14b8b46508acdf783e5d02b994030784411f35b71c6edc71869dc1] [0x37abfab6ab876ed7d3de591e89f3df99f731eaa4b33775f80afeee6fea4d471c]
//[0x0b4aa17bff8fc189efb37609ac5ea9fca0df4c834a6fbac74b24c8119c40fef2] [0x58cfb8b00d652ba783bf3be6f047e8035304fbf19bc6151afdcbf359e6396b38] [0xf72583988683f14adebd6eed8914c8b5a29217104a476f4b87d6e3716def3116] [0x6d7746a0c24e6f9bd5f5b81b97fcf98054c1b5dddc2a8e329389759e8a7f91e1] [0x3ceb0f2fe15be2a24edac38d32e1b42c55e20e749e1dc6cb8413e88a34c9be63] [0x3a85010bde3dd100d12fd21822af5330e07915a79d72f7c0496cdf000a802c68] [0x3c51f9c7246161d451b48056ccd272e947b6a9888ea0631b06484d4e51692659] [0x9c44f792603a5d0898e97afd5a0fa8946dcb97813640aa37eeb096769a012f95]
//[0x044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d] [0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6] [0xad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5] [0x2a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de] [0x13600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060] [0xceebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1] [0xe455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d] [0x52f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021] [0xe4b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10] [0xd2f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb] [0x1a192fabce13988b84994d4296e6cdc418d55e2f1d7f942188d4040b94fc57ac] [0x7880aec93413f117ef14bd4e6d130875ab2c7d7d55a064fac3c2f7bd51516380] [0x7f8b6b088b6d74c2852fc86c796dca07b44eed6fb3daf5e6b59f7c364db14528] [0x789bcdf275fa270780a52ae3b79bb1ce0fda7e0aaad87b57b74bb99ac290714a] [0x5c4c6aa067b6f8e6cb38e6ab843832a94d1712d661a04d73c517d6a1931a9e5d] [0x1d3be50b2bb17407dd170f1d5da128d1def30c6b1598d6a629e79b4775265526]

func TestDump(t *testing.T) {
	leaves := generateLeaves(16)
	tree, err := NewMerkeTree(sha3.NewLegacyKeccak256(), leaves)
	require.NoError(t, err)
	fmt.Println(tree.Dump())
}
