package merkle_patricia_trie

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/example/infra/db/merkle_patricia_trie/trie"
	"github.com/example/service/crypto"
	"github.com/pkg/errors"
)

type MerkleSet struct {
	hashes []trie.HashBlob
}

// Direct path from leaf to root
type MerklePath []MerkleSet

func (mp MerklePath) MarshalJSON() ([]byte, error) {
	bf := bytes.NewBufferString("[")
	for mpIndex, s := range mp {
		if mpIndex > 0 {
			bf.WriteByte(',')
		}
		bf.WriteByte('[')
		for setIndex, h := range s.hashes {
			if setIndex > 0 {
				bf.WriteByte(',')
			}
			bf.WriteByte('"')
			bf.WriteString(hex.EncodeToString(h))
			bf.WriteByte('"')
		}
		bf.WriteByte(']')
	}
	bf.WriteByte(']')
	return bf.Bytes(), nil
}

type MerklePatriciaTrie struct {
	hs   crypto.Hash
	root trie.NodeBranch
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (mt *MerklePatriciaTrie) commonPrefix(a, b string) (string, error) {
	if len(a) == 0 || len(b) == 0 {
		return "", fmt.Errorf("length of the string must be positive")
	}
	minLen := min(len(a), len(b))
	if a[0] != b[0] {
		return "", fmt.Errorf("no common prefix")
	}
	for i := 1; i < minLen; i++ {
		if a[i] != b[i] {
			return a[:i], nil
		}
	}
	return a[:minLen], nil
}

func (mt *MerklePatriciaTrie) insertToExtension(key string, valueObject trie.ValueObject, node trie.NodeExtension) error {
	// Current node key is the end of the inserting key
	if key == node.Key() {
		if node.HasValueObject() {
			return fmt.Errorf("MerklePatriciaTrie.insertKeyToExtension() failed. Key '%s' already exists", key)
		}
		node.SetValueObject(valueObject)
		return node.UpdateHash(mt.hs)
	}

	prefix, err := mt.commonPrefix(node.Key(), key)
	if err != nil {
		panic("Key must have the common prefix which has at least one character. err: " + err.Error())
	}

	// 1. Extend
	if prefix == node.Key() {
		keyTail := key[len(prefix):]
		if !node.HasNext() {
			newTailNode, err := trie.NewNodeExtension(keyTail, nil, valueObject, mt.hs)
			if err != nil {
				return err
			}
			node.SetNext(newTailNode)
			return node.UpdateHash(mt.hs)
		}

		switch next := node.Next().(type) {
		case trie.NodeExtension:
			if keyTail[0] == next.Key()[0] {
				if err := mt.insertToExtension(keyTail, valueObject, next); err != nil {
					return err
				}
				return node.UpdateHash(mt.hs)
			}
			newKeyNode, err := trie.NewNodeExtension(keyTail, nil, valueObject, mt.hs)
			if err != nil {
				return err
			}
			newBranch, err := trie.NewNodeBranchWithChildren(next, newKeyNode, mt.hs)
			if err != nil {
				return err
			}
			node.SetNext(newBranch)
			return node.UpdateHash(mt.hs)
		case trie.NodeBranch:
			if err := mt.insertToBranch(keyTail, valueObject, next); err != nil {
				return err
			}
			return node.UpdateHash(mt.hs)
		default:
			panic("Unknown node type")
		}
	}
	if prefix == key {
		keyTail := node.Key()[len(prefix):]
		tailNode, err := trie.NewNodeExtension(keyTail, node.Next(), node.ValueObject(), mt.hs)
		if err != nil {
			return err
		}

		node.SetKey(prefix)
		node.SetNext(tailNode)
		node.SetValueObject(valueObject)
		return node.UpdateHash(mt.hs)
	}

	// 2. Divide (Ext + Branch + Ext * 2)
	nodeKeyTail := node.Key()[len(prefix):]
	nodeTailNode, err := trie.NewNodeExtension(nodeKeyTail, node.Next(), node.ValueObject(), mt.hs)
	if err != nil {
		return err
	}

	newKeyTail := key[len(prefix):]
	newTailNode, err := trie.NewNodeExtension(newKeyTail, nil, valueObject, mt.hs)
	if err != nil {
		return err
	}

	newBranch, err := trie.NewNodeBranchWithChildren(nodeTailNode, newTailNode, mt.hs)
	if err != nil {
		return err
	}

	node.SetKey(prefix)
	node.SetNext(newBranch)
	node.SetValueObject(nil)

	return node.UpdateHash(mt.hs)
}

func (mt *MerklePatriciaTrie) insertToBranch(key string, valueObject trie.ValueObject, node trie.NodeBranch) error {
	if node.HasChildAt(key[0]) {
		if err := mt.insertToExtension(key, valueObject, node.ChildAt(key[0])); err != nil {
			return err
		}
		return node.UpdateHash(mt.hs)
	}
	n, err := trie.NewNodeExtension(key, nil, valueObject, mt.hs)
	if err != nil {
		return err
	}
	if err := node.Append(n); err != nil {
		return err
	}
	return node.UpdateHash(mt.hs)
}

func (mt *MerklePatriciaTrie) Insert(key []byte, value []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("length of key must be positive")
	}
	ek := hex.EncodeToString(key)
	vo := trie.NewValueObject(value)
	if err := mt.insertToBranch(ek, vo, mt.root); err != nil {
		return err
	}
	return mt.root.UpdateHash(mt.hs)
}

func (mt *MerklePatriciaTrie) deleteKeyInExtension(key string, node trie.NodeExtension) (shouldDelete bool, err error) {
	// Current node key is the end of the deleting key
	if key == node.Key() {
		if !node.HasValueObject() {
			return false, fmt.Errorf("deleteKey is not found")
		}
		if !node.HasNext() {
			return true, nil
		}
		// HasValueObject() && HasNext()
		switch next := node.Next().(type) {
		case trie.NodeExtension:
			node.SetKey(node.Key() + next.Key())
			node.SetValueObject(next.ValueObject())
			node.SetNext(next.Next())
			return false, node.UpdateHash(mt.hs)
		case trie.NodeBranch:
			return false, node.UpdateHash(mt.hs)
		default:
			panic("Unknown node type")
		}
	}

	prefix, err := mt.commonPrefix(node.Key(), key)
	if err != nil {
		panic(err)
	}
	if prefix == key {
		return false, fmt.Errorf("ValueObject not found")
	}

	if prefix != node.Key() {
		return false, fmt.Errorf("ValueObject not found")
	}

	keyTail := key[len(prefix):]
	if !node.HasNext() {
		return false, fmt.Errorf("ValueObject not found")
	}

	switch next := node.Next().(type) {
	case trie.NodeExtension:
		if keyTail[0] != next.Key()[0] {
			return false, fmt.Errorf("ValueObject not found")
		}
		sd, err := mt.deleteKeyInExtension(keyTail, next)
		if err != nil {
			return false, err
		}
		if !sd {
			return false, node.UpdateHash(mt.hs)
		}
		node.SetNext(nil)
		if node.HasValueObject() {
			return false, node.UpdateHash(mt.hs)
		} else {
			return true, nil
		}
	case trie.NodeBranch:
		sd, err := mt.deleteKeyInBranch(keyTail, next)
		if err != nil {
			return false, err
		}
		if !sd {
			return false, node.UpdateHash(mt.hs)
		}
		newNext := next.First()
		if node.HasValueObject() {
			node.SetNext(newNext)
			return false, node.UpdateHash(mt.hs)
		}
		if newNext == nil {
			panic("newNext must not be nil because the deleting branch must have one child.")
		}
		node.SetKey(node.Key() + newNext.Key())
		node.SetValueObject(newNext.ValueObject())
		node.SetNext(newNext.Next())
		return false, node.UpdateHash(mt.hs)
	default:
		panic("Unknown node type")
	}
}

func (mt *MerklePatriciaTrie) deleteKeyInBranch(key string, node trie.NodeBranch) (shouldDelete bool, err error) {
	c := key[0]
	if !node.HasChildAt(c) {
		return false, fmt.Errorf("ValueObject not found under branch = <%c>", c)
	}
	sd, err := mt.deleteKeyInExtension(key, node.ChildAt(c))
	if err != nil {
		return false, err
	}
	if !sd {
		return false, node.UpdateHash(mt.hs)
	}
	if err := node.Delete(c); err != nil {
		return false, err
	}
	if node.Count() == 1 {
		return true, nil
	}
	return false, node.UpdateHash(mt.hs)
}

func (mt *MerklePatriciaTrie) Delete(key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("length of key must be positive")
	}
	ek := hex.EncodeToString(key)
	// shouldDelete is ignored if branch node is root
	if _, err := mt.deleteKeyInBranch(ek, mt.root); err != nil {
		return errors.Wrapf(err, "failed to delete key = <%s>", ek)
	}
	return mt.root.UpdateHash(mt.hs)
}

func (mt *MerklePatriciaTrie) merklePathInExtension(key string, node trie.NodeExtension) (MerklePath, error) {
	if key == node.Key() {
		if !node.HasValueObject() {
			return nil, fmt.Errorf("ValueObject not found")
		}
		return MerklePath{MerkleSet{[]trie.HashBlob{node.Hash()}}}, nil
	}

	prefix, err := mt.commonPrefix(node.Key(), key)
	if err != nil {
		panic(err)
	}
	if prefix == key {
		return nil, fmt.Errorf("ValueObject not found")
	}

	if prefix != node.Key() {
		return nil, fmt.Errorf("ValueObject not found")
	}

	keyTail := key[len(prefix):]
	if !node.HasNext() {
		return nil, fmt.Errorf("ValueObject not found")
	}

	switch next := node.Next().(type) {
	case trie.NodeExtension:
		if keyTail[0] != next.Key()[0] {
			return nil, fmt.Errorf("ValueObject not found")
		}
		path, err := mt.merklePathInExtension(keyTail, next)
		if err != nil {
			return nil, err
		}
		return append(path, MerkleSet{[]trie.HashBlob{node.Hash()}}), nil
	case trie.NodeBranch:
		path, err := mt.merklePathInBranch(keyTail, next)
		if err != nil {
			return nil, err
		}
		return append(path, MerkleSet{[]trie.HashBlob{node.Hash()}}), nil
	default:
		panic("Unknown node type")
	}
}

func (mt *MerklePatriciaTrie) merklePathInBranch(key string, node trie.NodeBranch) (MerklePath, error) {
	c := key[0]
	if !node.HasChildAt(c) {
		return nil, fmt.Errorf("ValueObject not found under branch = <%c>", c)
	}
	path, err := mt.merklePathInExtension(key, node.ChildAt(c))
	if err != nil {
		return nil, err
	}
	var hs []trie.HashBlob
	for _, c := range node.ListChildren() {
		if c != nil {
			hs = append(hs, c.Hash())
		} else {
			hs = append(hs, nil)
		}
	}
	return append(path, MerkleSet{hs}), nil
}

func (mt *MerklePatriciaTrie) FindMerklePath(key []byte) (MerklePath, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("length of key must be positive")
	}
	ek := hex.EncodeToString(key)
	path, err := mt.merklePathInBranch(ek, mt.root)
	if err != nil {
		return nil, err
	}
	return append(path, MerkleSet{[]trie.HashBlob{mt.root.Hash()}}), nil
}

func NewMerklePatriciaTrie(hs crypto.Hash) *MerklePatriciaTrie {
	root := trie.NewNodeBranch()
	if err := root.UpdateHash(hs); err != nil {
		panic("Cannot initialize the root hash. Error of nodeBranch.UpdateHash(): " + err.Error())
	}
	return &MerklePatriciaTrie{hs, root}
}
