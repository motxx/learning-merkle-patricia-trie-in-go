package merkle_patricia_trie

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/example/entity"
	"github.com/example/service/crypto"
	"github.com/example/service/crypto/sha256"
)

func hashService(t *testing.T) crypto.Hash {
	sha256.NewSha256()
	hs, err := crypto.GetHashService(entity.HashSha256)
	if err != nil {
		t.Fatal(err)
	}
	return hs
}

func TestNewMerklePatriciaTrie(t *testing.T) {
	NewMerklePatriciaTrie(hashService(t))
}

func TestMerklePatriciaTrie_Insert(t *testing.T) {
	hs := hashService(t)

	{
		t.Log("Root hashes are consistent regardless of Insert() order")

		simple1 := [][]string{
			{"k12", "kab", "kac"},
			{"k12", "kac", "kab"},
			{"kab", "k12", "kac"},
			{"kab", "kac", "k12"},
			{"kac", "k12", "kab"},
			{"kac", "kab", "k12"},
		}
		simple2 := [][]string{
			{"dog", "cat", "doge"},
			{"dog", "doge", "cat"},
			{"cat", "dog", "doge"},
			{"cat", "doge", "dog"},
			{"doge", "dog", "cat"},
			{"doge", "cat", "dog"},
		}
		allExtension := [][]string{
			{"k", "kk", "kkk"},
			{"k", "kkk", "kk"},
			{"kk", "k", "kkk"},
			{"kk", "kkk", "k"},
			{"kkk", "k", "kk"},
			{"kkk", "kk", "k"},
		}

		for tcIndex, perms := range [][][]string{simple1, simple2, allExtension} {
			// t.Log("Insert perms[0] and verify no error.")
			trie := NewMerklePatriciaTrie(hs)
			for _, key := range perms[0] {
				if err := trie.Insert([]byte(key), []byte("value")); err != nil {
					t.Error(err)
				}
			}

			for permIndex := 1; permIndex < len(perms); permIndex++ {
				// t.Logf("Insert perms[%d] and verify the consistency with perms[0] root hash.", i)
				permTrie := NewMerklePatriciaTrie(hs)
				for _, key := range perms[permIndex] {
					if err := permTrie.Insert([]byte(key), []byte("value")); err != nil {
						t.Error(err)
					}
				}
				if !bytes.Equal(trie.root.Hash(), permTrie.root.Hash()) {
					rj, err := json.MarshalIndent(trie.root, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					t.Log(string(rj))
					j, err := json.MarshalIndent(permTrie.root, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					t.Log(string(j))
					t.Errorf("Inconsistent root hash at test index: <%d/%d>", tcIndex, permIndex)
				}
			}
		}
	}
	{
		t.Log("Insert B on the boundary between E->E")

		trie := NewMerklePatriciaTrie(hs)
		if err := trie.Insert([]byte("key"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		if err := trie.Insert([]byte("key123"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		if err := trie.Insert([]byte("keyxyz"), []byte("value")); err != nil {
			t.Error(err)
		}
	}
	{
		t.Log("valueObject is serialized by hash")

		trie1 := NewMerklePatriciaTrie(hs)
		if err := trie1.Insert([]byte("key"), []byte("value1")); err != nil {
			t.Fatal(err)
		}
		trie2 := NewMerklePatriciaTrie(hs)
		if err := trie2.Insert([]byte("key"), []byte("value2")); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(trie1.root.Hash(), trie2.root.Hash()) {
			t.Error("Different value must produce different root hash")
		}
	}
}

func TestMerklePatriciaTrie_Delete(t *testing.T) {
	hs := hashService(t)

	{
		t.Log("Root hashes are consistent regardless of Delete() order")

		type testType struct {
			want    [][]string
			input   [][]string
			initial []string
		}

		simple1 := testType{
			[][]string{
				{"k12"},
				{"kab"},
				{"kac"},
				{"k12", "kab"},
				{"k12", "kac"},
				{"kab", "kac"},
			},
			[][]string{
				{"k12"},
				{"kab"},
				{"kac"},
				{"k12", "kab"},
				{"kab", "k12"},
				{"k12", "kac"},
				{"kac", "k12"},
				{"kab", "kac"},
				{"kac", "kab"},
			},
			[]string{"k12", "kab", "kac"},
		}

		simple2 := testType{
			[][]string{
				{"dog"},
				{"cat"},
				{"doge"},
				{"dog", "cat"},
				{"dog", "doge"},
				{"cat", "doge"},
			},
			[][]string{
				{"dog"},
				{"cat"},
				{"doge"},
				{"dog", "cat"},
				{"cat", "dog"},
				{"dog", "doge"},
				{"doge", "dog"},
				{"cat", "doge"},
				{"doge", "cat"},
			},
			[]string{"dog", "cat", "doge"},
		}

		allExtension := testType{
			[][]string{
				{"k"},
				{"kk"},
				{"kkk"},
				{"k", "kk"},
				{"k", "kkk"},
				{"kk", "kkk"},
			},
			[][]string{
				{"k"},
				{"kk"},
				{"kkk"},
				{"k", "kk"},
				{"kk", "k"},
				{"k", "kkk"},
				{"kkk", "k"},
				{"kk", "kkk"},
				{"kkk", "kk"},
			},
			[]string{"k", "kk", "kkk"},
		}

		for testIndex, test := range []testType{simple1, simple2, allExtension} {
			// Setup
			invertedIndex := make(map[string]struct{})
			for _, perm := range test.want {
				trie := NewMerklePatriciaTrie(hs)
				for _, key := range perm {
					if err := trie.Insert([]byte(key), []byte("value")); err != nil {
						t.Fatal(err)
					}
				}
				invertedIndex[string(trie.root.Hash())] = struct{}{}
			}

			// Verify
			for permIndex, deletes := range test.input {
				trie := NewMerklePatriciaTrie(hs)
				for _, key := range test.initial {
					if err := trie.Insert([]byte(key), []byte("value")); err != nil {
						t.Fatal(err)
					}
				}
				for _, key := range deletes {
					if err := trie.Delete([]byte(key)); err != nil {
						t.Fatal(err)
					}
				}
				if _, ok := invertedIndex[string(trie.root.Hash())]; !ok {
					j, err := json.MarshalIndent(trie.root, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					t.Log(string(j))
					t.Errorf("Inconsistent root hash at test index: <%d/%d>", testIndex, permIndex)
				}
			}
		}
	}
	{
		t.Log("Mismatch key on the boundary between E->E")

		trie := NewMerklePatriciaTrie(hs)
		if err := trie.Insert([]byte("key"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		if err := trie.Insert([]byte("key123"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		if err := trie.Delete([]byte("keyxyz")); err == nil {
			t.Error("Cannot delete non-existent key")
		}
	}
}

func TestMerklePatriciaTrie_FindMerklePath(t *testing.T) {
	hs := hashService(t)

	{
		trie := NewMerklePatriciaTrie(hs)
		if err := trie.Insert([]byte("key"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		path, err := trie.FindMerklePath([]byte("key"))
		if err != nil {
			t.Error(err)
		}
		j, err := json.Marshal(path)
		r := regexp.MustCompile(`^\[\["[\d\w]{64}"\],\[[",]*"[\d\w]{64}"[",]*\],\["[\d|\w]{64}"\]\]$`)
		if !r.MatchString(string(j)) {
			t.Errorf("Merkle path is invalid.\n  got = %s\n  want = %s", j, r.String())
		}
		if !bytes.Equal(trie.root.Hash(), path[2].hashes[0]) {
			t.Error("Root hash is inconsistent")
		}

		if err := trie.Insert([]byte("key123"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		path, err = trie.FindMerklePath([]byte("key123"))
		if err != nil {
			t.Error(err)
		}
		j, err = json.Marshal(path)
		r = regexp.MustCompile(`^\[\["[\d\w]{64}"\],\["[\d\w]{64}"\],\[[",]*"[\d\w]{64}"[",]*\],\["[\d|\w]{64}"\]\]$`)
		if !r.MatchString(string(j)) {
			t.Errorf("Merkle path is invalid.\n  got = %s\n  want = %s", j, r.String())
		}
		if !bytes.Equal(trie.root.Hash(), path[3].hashes[0]) {
			t.Error("Root hash is inconsistent")
		}

		if err := trie.Insert([]byte("key12ab"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		path, err = trie.FindMerklePath([]byte("key12ab"))
		if err != nil {
			t.Error(err)
		}
		j, err = json.Marshal(path)
		r = regexp.MustCompile(`^\[\["[\d\w]{64}"\],\[[",]*"[\d\w]{64}"[",]*[\d\w]{64}"[",]*\],\["[\d\w]{64}"\],\["[\d\w]{64}"\],\[[",]*"[\d\w]{64}"[",]*\],\["[\d|\w]{64}"\]\]$`)
		if !r.MatchString(string(j)) {
			t.Errorf("Merkle path is invalid.\n  got = %s\n  want = %s", j, r.String())
		}
		if !bytes.Equal(trie.root.Hash(), path[5].hashes[0]) {
			t.Error("Root hash is inconsistent")
		}
	}
	{
		t.Log("Mismatch key on the boundary between E->E")

		trie := NewMerklePatriciaTrie(hs)
		if err := trie.Insert([]byte("key"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		if err := trie.Insert([]byte("key123"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		if _, err := trie.FindMerklePath([]byte("keyxyz")); err == nil {
			t.Error("Cannot delete non-existent key")
		}
	}
}
