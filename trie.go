package trie

import (
	"bytes"

	"encoding/gob"

	"encoding/hex"

	"fmt"

	"github.com/example/logger"

	"github.com/example/service/crypto"

	"github.com/pkg/errors"
)

var log = logger.NewLogger()

const ChildIndexCount = 16

type HashBlob []byte

type Node interface {
	Serialize() ([]byte, error)

	UpdateHash(crypto.Hash) error

	Hash() HashBlob

	MarshalJSON() ([]byte, error)
}

type NodeExtension interface {
	Node

	Key() string

	SetKey(string)

	Next() Node

	HasNext() bool

	SetNext(Node)

	ValueObject() ValueObject

	HasValueObject() bool

	SetValueObject(ValueObject)
}

type ValueObject interface {
	Value() []byte
}

type NodeBranch interface {
	Node

	ListChildren() []NodeExtension

	HasChildAt(byte) bool

	ChildAt(byte) NodeExtension

	Append(NodeExtension) error

	Delete(byte) error

	Count() int

	First() NodeExtension
}

func NewNodeExtension(key string, next Node, valueObject ValueObject, hs crypto.Hash) (NodeExtension, error) {

	base := nodeBase{HashBlob{}}

	n := &nodeExtension{base, key, next, valueObject}

	if err := n.UpdateHash(hs); err != nil {

		return nil, err

	}

	return n, nil

}

func NewValueObject(value []byte) ValueObject {

	return &valueObject{value}

}

func NewNodeBranch() NodeBranch {

	base := nodeBase{HashBlob{}}

	children := make([]NodeExtension, ChildIndexCount)

	return &nodeBranch{base, children}

}

func NewNodeBranchWithChildren(a, b NodeExtension, hs crypto.Hash) (NodeBranch, error) {

	children := make([]NodeExtension, ChildIndexCount)

	if len(a.Key()) == 0 || len(b.Key()) == 0 {

		return nil, fmt.Errorf("key is empty")

	}

	if a.Key()[0] == b.Key()[0] {

		return nil, fmt.Errorf("two children have duplicate index")

	}

	children[toChildIndex(a.Key()[0])] = a

	children[toChildIndex(b.Key()[0])] = b

	base := nodeBase{[]byte{}}

	n := &nodeBranch{base, children}

	if err := n.UpdateHash(hs); err != nil {

		return nil, err

	}

	return n, nil

}

type nodeBase struct {
	hash HashBlob
}

func (node *nodeBase) Hash() HashBlob {

	if len(node.hash) == 0 {

		panic("Hash is empty")

	}

	return node.hash

}

type nodeExtension struct {
	nodeBase

	key string

	next Node

	value ValueObject
}

func (node *nodeExtension) Serialize() ([]byte, error) {

	w := new(bytes.Buffer)

	encoder := gob.NewEncoder(w)

	if err := encoder.Encode("E"); err != nil {

		return nil, err

	}

	if err := encoder.Encode(node.key); err != nil {

		return nil, err

	}

	if node.HasNext() {

		if err := encoder.Encode("C"); err != nil {

			return nil, err

		}

		if err := encoder.Encode(node.next.Hash()); err != nil {

			return nil, err

		}

	} else {

		if err := encoder.Encode([]byte("NC")); err != nil {

			return nil, err

		}

	}

	if node.HasValueObject() {

		if err := encoder.Encode("V"); err != nil {

			return nil, err

		}

		if err := encoder.Encode(node.value.Value()); err != nil {

			return nil, err

		}

	} else {

		if err := encoder.Encode("NV"); err != nil {

			return nil, err

		}

	}

	return w.Bytes(), nil

}

func (node *nodeExtension) UpdateHash(hs crypto.Hash) error {

	s, err := node.Serialize()

	if err != nil {

		return errors.Wrap(err, "updateHash failed")

	}

	res, err := hs.Hash(s)

	if err != nil {

		return errors.Wrap(err, "updateHash failed")

	}

	node.hash = res

	return nil

}

func (node *nodeExtension) MarshalJSON() ([]byte, error) {

	bf := bytes.NewBufferString("{")

	bf.WriteString("\"type\":\"Extension\",")

	bf.WriteString("\"key\":\"" + node.key + "\",")

	if node.HasNext() {

		j, err := node.next.MarshalJSON()

		if err != nil {

			return nil, err

		}

		bf.WriteString("\"next\":" + string(j) + ",")

	} else {

		bf.WriteString("\"next\":null,")

	}

	bf.WriteString("\"value\":")

	if node.HasValueObject() {

		marshalValue := node.value.Value()

		if len(marshalValue) > 100 {

			log.Warn("Too large value in MarshalJSON() (omitted)")

			marshalValue = marshalValue[:100]

		}

		bf.WriteString("\"" + hex.EncodeToString(marshalValue) + "\",")

	} else {

	}

	if len(node.hash) > 0 {

		bf.WriteString("\"hex_hash\":\"" + hex.EncodeToString(node.hash) + "\"")

	} else {

		bf.WriteString("\"hex_hash\":\"\"")

	}

	bf.WriteByte('}')

	return bf.Bytes(), nil

}

func (node *nodeExtension) Key() string {

	return node.key

}

func (node *nodeExtension) SetKey(key string) {

	if len(key) == 0 {

		panic("Cannot set empty key")

	}

	node.key = key

}

func (node *nodeExtension) Next() Node {

	return node.next

}

func (node *nodeExtension) HasNext() bool {

	return node.next != nil

}

func (node *nodeExtension) SetNext(n Node) {

	node.next = n

}

func (node *nodeExtension) ValueObject() ValueObject {

	return node.value

}

func (node *nodeExtension) HasValueObject() bool {

	return node.value != nil

}

func (node *nodeExtension) SetValueObject(value ValueObject) {

	node.value = value

}

type valueObject struct {
	value []byte
}

func (v *valueObject) Value() []byte {

	return v.value

}

type nodeBranch struct {
	nodeBase

	children []NodeExtension
}

func (node *nodeBranch) Serialize() ([]byte, error) {

	w := new(bytes.Buffer)

	encoder := gob.NewEncoder(w)

	if err := encoder.Encode("B"); err != nil {

		return nil, err

	}

	for _, child := range node.ListChildren() {

		if child != nil {

			if err := encoder.Encode("C"); err != nil {

				return nil, err

			}

			if err := encoder.Encode(child.Hash()); err != nil {

				return nil, err

			}

		} else {

			if err := encoder.Encode("NC"); err != nil {

				return nil, err

			}

		}

	}

	return w.Bytes(), nil

}

func (node *nodeBranch) UpdateHash(hs crypto.Hash) error {

	s, err := node.Serialize()

	if err != nil {

		return errors.Wrap(err, "UpdateHash() failed")

	}

	res, err := hs.Hash(s)

	if err != nil {

		return errors.Wrap(err, "UpdateHash() failed")

	}

	node.hash = res

	return nil

}

func (node *nodeBranch) ListChildren() []NodeExtension {

	return node.children

}

func (node *nodeBranch) HasChildAt(c byte) bool {

	return node.children[toChildIndex(c)] != nil

}

func (node *nodeBranch) ChildAt(c byte) NodeExtension {

	return node.children[toChildIndex(c)]

}

func (node *nodeBranch) Append(n NodeExtension) error {

	c := n.Key()[0]

	index := toChildIndex(c)

	if node.children[index] != nil {

		return fmt.Errorf("nodeBranch.Append() failed. Child node already exists at '%c'", c)

	}

	node.children[index] = n

	return nil

}

func (node *nodeBranch) Delete(c byte) error {

	index := toChildIndex(c)

	if node.children[index] == nil {

		return fmt.Errorf("nodeBranch.Delete() failed. Child node does not exist at '%c'", c)

	}

	node.children[index] = nil

	return nil

}

func (node *nodeBranch) Count() int {

	c := 0

	for _, child := range node.children {

		if child != nil {

			c++

		}

	}

	return c

}

func (node *nodeBranch) First() NodeExtension {

	for _, child := range node.children {

		if child != nil {

			return child

		}

	}

	return nil

}

func (node *nodeBranch) MarshalJSON() ([]byte, error) {

	bf := bytes.NewBufferString("{")

	bf.WriteString("\"type\":\"Branch\",")

	bf.WriteString("\"children\":[")

	for index, child := range node.children {

		if index > 0 {

			bf.WriteByte(',')

		}

		if child != nil {

			data, err := child.MarshalJSON()

			if err != nil {

				return nil, err

			}

			bf.Write(data)

		} else {

			bf.WriteString("null")

		}

	}

	bf.WriteString("],")

	if len(node.hash) > 0 {

		bf.WriteString("\"hex_hash\":\"" + hex.EncodeToString(node.hash) + "\"")

	} else {

		bf.WriteString("\"hex_hash\":\"\"")

	}

	bf.WriteByte('}')

	return bf.Bytes(), nil

}

func toChildIndex(ch byte) int {

	if '0' <= ch && ch <= '9' {

		return int(ch) - '0'

	} else if 'a' <= ch && ch <= 'f' {

		return int(ch) - 'a'

	} else {

		panic("Invalid child index")

	}

}
