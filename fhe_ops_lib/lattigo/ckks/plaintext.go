package ckks

import (
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/rlwe"
)

// Plaintext is is a Element with only one Poly.
type Plaintext struct {
	*rlwe.Plaintext
	Scale float64
}

type PlaintextRingT Plaintext

type PlaintextMul Plaintext

// NewPlaintext creates a new Plaintext of level level and scale scale.
func NewPlaintext(params Parameters, level int, scale float64) *Plaintext {
	pt := &Plaintext{Plaintext: rlwe.NewPlaintext(params.Parameters, level), Scale: scale}
	pt.Value.IsNTT = true
	return pt
}

func NewPlaintextMul(params Parameters, level int, scale float64) *PlaintextMul {
	pt := &PlaintextMul{Plaintext: rlwe.NewPlaintext(params.Parameters, level), Scale: scale}
	pt.Value.IsNTT = true
	pt.Value.IsMForm = true
	return pt
}

func NewPlaintextRingT(params Parameters, scale float64) *PlaintextRingT {
	plaintext := &PlaintextRingT{Plaintext: rlwe.NewPlaintext(params.Parameters, 0), Scale: scale}
	return plaintext
}

// ScalingFactor returns the scaling factor of the plaintext
func (p *Plaintext) ScalingFactor() float64 {
	return p.Scale
}

func (p *PlaintextMul) ScalingFactor() float64 {
	return p.Scale
}

// SetScalingFactor sets the scaling factor of the target plaintext
func (p *Plaintext) SetScalingFactor(scale float64) {
	p.Scale = scale
}

func (p *PlaintextMul) SetScalingFactor(scale float64) {
	p.Scale = scale
}

// NewPlaintextAtLevelFromPoly construct a new Plaintext at a specific level
// where the message is set to the passed poly. No checks are performed on poly and
// the returned Plaintext will share its backing array of coefficient.
func NewPlaintextAtLevelFromPoly(level int, poly *ring.Poly) *Plaintext {
	pt := rlwe.NewPlaintextAtLevelFromPoly(level, poly)
	pt.Value.IsNTT = true
	return &Plaintext{Plaintext: pt, Scale: 0}
}
