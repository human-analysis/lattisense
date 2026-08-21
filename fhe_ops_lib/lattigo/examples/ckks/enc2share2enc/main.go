package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/rlwe"
)

func main() {
	param_literal := ckks.PN14QP438
	param, _ := ckks.NewParametersFromLiteral(param_literal)

	kgen := ckks.NewKeyGenerator(param)
	sk := kgen.GenSecretKey()
	encryptor := ckks.NewEncryptor(param, sk)
	decryptor := ckks.NewDecryptor(param, sk)
	encoder := ckks.NewEncoder(param)
	encoder_big := ckks.NewEncoderBigComplex(param, 128)
	evaluator := ckks.NewEvaluator(param, rlwe.EvaluationKey{})

	repeat := 10
	input_level := 1

	for sigma := 24; sigma < 48; sigma++ {
		sum := 0.0
		for j := 0; j < repeat; j++ {
			x := (0.9 + rand.Float64()*0.2)
			x_mg := make([]float64, param.Slots())
			x_mg[0] = x
			x_pt := encoder.EncodeNew(x_mg, input_level, param.DefaultScale(), param.LogSlots())
			x_ct := encryptor.EncryptNew(x_pt)

			x1 := (-1.0 + rand.Float64()*2.0) * math.Pow(2, float64(sigma))
			// x1_mg := make([]float64, param.Slots())
			// x1_mg[0] = x1
			// x1_pt := encoder.EncodeNew(x1_mg, input_level, param.DefaultScale(), param.LogSlots())
			x1_mg := make([]*ring.Complex, param.Slots())
			x1_mg[0] = ring.NewComplex(big.NewFloat(x1), big.NewFloat(0.0))
			for k := 1; k < param.Slots(); k++ {
				x1_mg[k] = ring.NewComplex(big.NewFloat(0.0), big.NewFloat(0.0))
			}
			x1_pt := encoder_big.EncodeNew(x1_mg, input_level, param.DefaultScale(), param.LogSlots())
			x1_pt_prime := encoder_big.EncodeNew(x1_mg, param.MaxLevel(), param.DefaultScale(), param.LogSlots())

			x0_ct := evaluator.SubNew(x_ct, x1_pt)
			x0_pt := decryptor.DecryptNew(x0_ct)
			x0_mg := encoder_big.Decode(x0_pt, param.LogSlots())

			x0_pt_prime := encoder_big.EncodeNew(x0_mg, param.MaxLevel(), param.DefaultScale(), param.LogSlots())
			x0_ct_prime := encryptor.EncryptNew(x0_pt_prime)

			x_ct_prime := evaluator.AddNew(x0_ct_prime, x1_pt_prime)

			x_pt_prime := decryptor.DecryptNew(x_ct_prime)
			x_mg_prime := encoder.Decode(x_pt_prime, param.LogSlots())
			x_prime := real(x_mg_prime[0])
			// fmt.Printf("x'=%.8f, x=%.8f, x1=%.8f, x0=%v\n", x_prime, x, x1, x0_mg[0])
			diff := math.Abs(x_prime - x)
			sum += diff
		}
		fmt.Printf("sigma=%d, diff=%e\n", sigma, sum/float64(repeat))
	}
}
