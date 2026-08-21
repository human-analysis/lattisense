package bfv

import (
	"bytes"

	"github.com/cipherflow-fhe/lattigo/rlwe"
	"github.com/cipherflow-fhe/lattigo/utils"
)

// Ciphertext is a *ring.Poly array representing a polynomial of degree > 0 with coefficients in R_Q.
type Ciphertext struct {
	*rlwe.Ciphertext
}

type CompressedCiphertext struct {
	*rlwe.CompressedCiphertext
}

// NewCiphertext creates a new ciphertext parameterized by degree and at the max level.
func NewCiphertext(params Parameters, degree int) (ciphertext *Ciphertext) {
	return &Ciphertext{rlwe.NewCiphertext(params.Parameters, degree, params.MaxLevel())}
}

// NewCiphertextLvl creates a new ciphertext parameterized by degree and level.
func NewCiphertextLvl(params Parameters, degree, level int) (ciphertext *Ciphertext) {
	return &Ciphertext{rlwe.NewCiphertext(params.Parameters, degree, level)}
}

// NewCiphertextRandom generates a new uniformly distributed ciphertext of given degree at maximum level.
func NewCiphertextRandom(prng utils.PRNG, params Parameters, degree int) (ciphertext *Ciphertext) {
	return &Ciphertext{rlwe.NewCiphertextRandom(prng, params.Parameters, degree, params.MaxLevel())}
}

// NewCiphertextRandomLvl generates a new uniformly distributed ciphertext of given degree and level.
func NewCiphertextRandomLvl(prng utils.PRNG, params Parameters, degree, level int) (ciphertext *Ciphertext) {
	return &Ciphertext{rlwe.NewCiphertextRandom(prng, params.Parameters, degree, level)}
}

func NewCompressedCiphertext(params Parameters, degree int, level int) (ciphertext *CompressedCiphertext) {
	return &CompressedCiphertext{rlwe.NewCompressedCiphertext(params.Parameters, degree, level)}
}

// CopyNew creates a deep copy of the receiver ciphertext and returns it.
func (ct *Ciphertext) CopyNew() *Ciphertext {
	return &Ciphertext{ct.Ciphertext.CopyNew()}
}

// MarshalBinary encodes a Ciphertext in a byte slice.
func (ct *Ciphertext) MarshalBinary() (data []byte, err error) {
	return ct.Ciphertext.MarshalBinary()
}

func (ct *Ciphertext) ToBytes(param *rlwe.Parameters, n_drop_bit_0 int, n_drop_bit_1 int) []byte {
	writer := new(bytes.Buffer)

	rlwe.CiphertextToBytes(ct.Ciphertext, param, n_drop_bit_0, n_drop_bit_1, writer)

	return writer.Bytes()
}

func (ct *CompressedCiphertext) MarshalBinary() (data []byte, err error) {
	return ct.CompressedCiphertext.MarshalBinary()
}

func (ct *CompressedCiphertext) ToBytes(param *rlwe.Parameters) []byte {
	writer := new(bytes.Buffer)

	rlwe.CompressedCiphertextToBytes(ct.CompressedCiphertext, param, writer)

	return writer.Bytes()
}

// UnmarshalBinary decodes a previously marshaled Ciphertext in the target Ciphertext.
func (ct *Ciphertext) UnmarshalBinary(data []byte) (err error) {
	ct.Ciphertext = new(rlwe.Ciphertext)
	return ct.Ciphertext.UnmarshalBinary(data)
}

func (ct *Ciphertext) FromBytes(data []byte) {
	reader := bytes.NewReader(data)

	rlwe_ct := rlwe.BytesToCiphertext(reader)
	ct.Ciphertext = &rlwe_ct
}

func (ct *CompressedCiphertext) UnmarshalBinary(data []byte) (err error) {
	ct.CompressedCiphertext = new(rlwe.CompressedCiphertext)
	return ct.CompressedCiphertext.UnmarshalBinary(data)
}

func (ct *CompressedCiphertext) FromBytes(data []byte) {
	reader := bytes.NewReader(data)

	rlwe_cct := rlwe.BytesToCompressedCiphertext(reader)
	ct.CompressedCiphertext = &rlwe_cct
}

// GetDataLen returns the length in bytes of the target Ciphertext.
func (ct *Ciphertext) GetDataLen(WithMetaData bool) (dataLen int) {
	return ct.Ciphertext.GetDataLen(WithMetaData)
}

func (ct_in *CompressedCiphertext) ToCiphertext(params Parameters) *Ciphertext {
	return &Ciphertext{ct_in.CompressedCiphertext.ToCiphertext(params.Parameters)}
}
