package main

/*
#include "../../fhe_types_v2.h"
*/
import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"reflect"
	"runtime"
	"runtime/cgo"
	"sort"
	"strconv"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/bfv"
	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/rlwe"
	"github.com/cipherflow-fhe/lattigo/rlwe/ringqp"
)

type RlweContext struct {
	compressed bool
	sk         *rlwe.SecretKey
	pk         *rlwe.PublicKey
	rlk        *rlwe.RelinearizationKey
	gk         *rlwe.RotationKeySet
	kgen       rlwe.KeyGenerator
}

type BfvContext struct {
	parameter *bfv.Parameters
	RlweContext

	encoder      bfv.Encoder
	encryptor_sk bfv.Encryptor
	encryptor_pk bfv.Encryptor
	decryptor    bfv.Decryptor
	evaluator    bfv.Evaluator
}

type CkksContext struct {
	support_big_complex bool

	parameter *ckks.Parameters
	RlweContext

	encoder      ckks.Encoder
	encoder_big  ckks.EncoderBigComplex
	encryptor_sk ckks.Encryptor
	encryptor_pk ckks.Encryptor
	decryptor    ckks.Decryptor
	evaluator    ckks.Evaluator
}

var fpga_parameter_handle uint64
var error_message string

var bfv_q []uint64
var ckks_q []uint64

func init() {
	bfv_q = []uint64{0x7f4e0001, 0x7fb40001, 0x7fd20001, 0x7fea0001, 0x7ff80001, 0x7ffe0001}
	ckks_q = []uint64{0x7f4e0001, 0x7fb40001, 0x7fd20001, 0x7fea0001, 0x7ff80001, 0x7ffe0001}

	// lattigo 中密文乘法 Mul函数基于环 ringQ 与 ringQMul, 其中 ringQMul 是与Q与P无关的新生成的环, 具体见bfv/params.go 167行
	// lattigo 中 Q 与 P 用于生成公钥、私钥以及relinKey，加密，relin
	// fpga_param_literal := bfv.ParametersLiteral{
	// 	LogN:  13,
	// 	T:     0x1b4001,
	// 	Q:     bfv_q,
	// 	P:     []uint64{0xff5a0001},
	// 	Sigma: rlwe.DefaultSigma,
	// }
	// fpga_param, err := bfv.NewParametersFromLiteral(fpga_param_literal)
	// if err != nil {
	// 	panic(err)
	// }
	// fpga_parameter_handle = insert_object(&fpga_param)

}

func insert_object(item any) uint64 {
	h := cgo.NewHandle(item)
	return uint64(h)
}

func get_object[T any](handle_id uint64) *T {
	h := cgo.Handle(handle_id)
	object := h.Value().(*T)
	return object
}

func delete_object(handle_id uint64) {
	h := cgo.Handle(handle_id)
	h.Delete()
}

func get_ckks_context(context_handle uint64) *CkksContext {
	h := cgo.Handle(context_handle)
	context_any := h.Value()

	var context *CkksContext
	if reflect.TypeOf(context_any) == reflect.TypeFor[*CkksContext]() {
		context = reflect.ValueOf(context_any).Interface().(*CkksContext)
	} else if reflect.TypeOf(context_any) == reflect.TypeFor[*CkksBtpContext]() {
		context = &reflect.ValueOf(context_any).Interface().(*CkksBtpContext).CkksContext
	} else {
		panic("context_handle is not CkksContext or CkksBtpContext.")
	}
	return context
}

func convert_slice(x []int32) []int {
	y := make([]int, len(x))
	for i, v := range x {
		y[i] = int(v)
	}
	return y
}

//export GetErrorMessage
func GetErrorMessage() *C.char {
	return C.CString(error_message)
}

//export CreateBfvParameter
func CreateBfvParameter(N uint64, T uint64) uint64 {
	var literal bfv.ParametersLiteral
	switch N {
	case 2048:
		literal = bfv.PN11QP54
	case 4096:
		literal = bfv.PN12QP109
	case 8192:
		literal = bfv.PN13QP218
	case 16384:
		literal = bfv.PN14QP438
	case 32768:
		literal = bfv.PN15QP880
	default:
		panic("Poly degree N not supported.")
	}
	literal.T = T
	param, err := bfv.NewParametersFromLiteral(literal)
	if err != nil {
		panic(err)
	}

	id := insert_object(&param)
	return id
}

//export CreateCustomBfvParameter
func CreateCustomBfvParameter() uint64 {
	param_literal := bfv.ParametersLiteral{
		LogN:  14,
		T:     65537,
		Q:     []uint64{0x7f000001, 0x7f180001, 0x7f3c0001, 0x7f420001, 0x7f440001, 0x7f4e0001, 0x7fb40001, 0x7fd20001, 0x7fea0001, 0x7ff80001, 0x7ffe0001, 0xffa20001, 0xffac0001},
		P:     []uint64{0xffd20001, 0xfff00001},
		Sigma: rlwe.DefaultSigma,
	}
	param, err := bfv.NewParametersFromLiteral(param_literal)
	if err != nil {
		panic(err)
	}

	id := insert_object(&param)
	return id
}

//export CreateCustomCkksParameter
func CreateCustomCkksParameter() uint64 {
	param_literal := ckks.ParametersLiteral{
		LogN:         14,
		Q:            []uint64{4288184321, 4288806913, 4288905217, 4289462273, 4291952641, 4292018177, 4292116481, 4292149249, 4292313089, 4292804609, 4293230593, 4293918721},
		P:            []uint64{4294475777},
		LogSlots:     13,
		DefaultScale: 1 << 31,
	}
	// param, err := ckks.NewParametersFromLiteral(param_literal)
	// if err != nil {
	// 	panic(err)
	// }

	// id := insert_object(&param)
	param, err := ckks.NewParametersFromLiteral(param_literal)
	if err != nil {
		panic(err)
	}

	id := insert_object(&param)
	return id
}

//export CreateCkksParameter
func CreateCkksParameter(N uint64) uint64 {
	var literal ckks.ParametersLiteral
	switch N {
	case 4096:
		literal = ckks.PN12QP109
	case 8192:
		literal = ckks.PN13QP218
	case 16384:
		literal = ckks.PN14QP438
	case 32768:
		literal = ckks.PN15QP880
	case 65536:
		literal = ckks.PN16QP1761
	default:
		panic("Poly degree N not supported.")
	}
	param, err := ckks.NewParametersFromLiteral(literal)
	if err != nil {
		panic(err)
	}

	id := insert_object(&param)
	return id
}

//export CreateBfvParameterV2
func CreateBfvParameterV2(T uint64) uint64 {
	param_literal := bfv.ParametersLiteral{
		LogN:  13,
		T:     T,
		Q:     bfv_q,
		P:     []uint64{0xff5a0001},
		Sigma: rlwe.DefaultSigma,
	}

	param, err := bfv.NewParametersFromLiteral(param_literal)
	if err != nil {
		panic(err)
	}

	param.IsFpga = true // only for v0.7

	id := insert_object(&param)
	return id
}

//export CreateCkksParameterV2
func CreateCkksParameterV2() uint64 {
	param_literal := ckks.ParametersLiteral{
		LogN:  13,
		Q:     ckks_q,
		P:     []uint64{0xff5a0001},
		Sigma: rlwe.DefaultSigma,
	}

	param, err := ckks.NewParametersFromLiteral(param_literal)
	if err != nil {
		panic(err)
	}

	param.IsFpga = true // only for v0.7

	id := insert_object(&param)
	return id
}

//export SetBfvParameter
func SetBfvParameter(N uint64, T uint64, Q *C.uint64_t, q_len int, P *C.uint64_t, p_len int) uint64 {
	q_slice := unsafe.Slice((*uint64)(Q), q_len)
	p_slice := unsafe.Slice((*uint64)(P), p_len)

	param_literal := bfv.ParametersLiteral{
		LogN:  bits.Len64(N) - 1,
		T:     T,
		Q:     q_slice,
		P:     p_slice,
		Sigma: rlwe.DefaultSigma,
	}

	param, err := bfv.NewParametersFromLiteral(param_literal)
	if err != nil {
		panic(err)
	}

	id := insert_object(&param)
	return id
}

//export SetCkksParameter
func SetCkksParameter(N uint64, Q *C.uint64_t, q_len int, P *C.uint64_t, p_len int) uint64 {
	q_slice := unsafe.Slice((*uint64)(Q), q_len)
	p_slice := unsafe.Slice((*uint64)(P), p_len)

	param_literal := ckks.ParametersLiteral{
		LogN:         bits.Len64(N) - 1,
		LogSlots:     bits.Len64(N) - 2,
		Q:            q_slice,
		P:            p_slice,
		DefaultScale: 1 << 40, // Default scale
		Sigma:        rlwe.DefaultSigma,
	}

	param, err := ckks.NewParametersFromLiteral(param_literal)
	if err != nil {
		panic(err)
	}

	id := insert_object(&param)
	return id
}

//export CopyBfvParameter
func CopyBfvParameter(parameter_handle uint64) uint64 {
	param := get_object[bfv.Parameters](parameter_handle)
	id := insert_object(param)
	return id
}

//export CopyCkksParameter
func CopyCkksParameter(parameter_handle uint64) uint64 {
	param := get_object[ckks.Parameters](parameter_handle)
	id := insert_object(param)
	return id
}

//export PrintBfvParameter
func PrintBfvParameter(parameter_handle uint64) {
	param := get_object[bfv.Parameters](parameter_handle)
	fmt.Printf("N = %d\n", param.N())
	fmt.Printf("RingQ: [")
	for _, q := range param.Q() {
		fmt.Printf("%d, ", q)
	}
	fmt.Printf("\b\b]\n")
	fmt.Printf("RingP: [")
	for _, q := range param.P() {
		fmt.Printf("%d, ", q)
	}
	fmt.Printf("\b\b]\n")
	fmt.Printf("T = %d\n", param.T())
}

//export PrintCkksParameter
func PrintCkksParameter(parameter_handle uint64) {
	param := get_object[ckks.Parameters](parameter_handle)
	fmt.Printf("N = %d\n", param.N())
	fmt.Printf("RingQ: [")
	for _, q := range param.Q() {
		fmt.Printf("%d, ", q)
	}
	fmt.Printf("\b\b]\n")
	fmt.Printf("RingP: [")
	for _, q := range param.P() {
		fmt.Printf("%d, ", q)
	}
	fmt.Printf("\b\b]\n")
}

//export GetBfvQ
func GetBfvQ(parameter_handle uint64, index int) uint64 {
	param := get_object[bfv.Parameters](parameter_handle)
	return param.Q()[index]
}

//export GetBfvQCount
func GetBfvQCount(parameter_handle uint64) int {
	param := get_object[bfv.Parameters](parameter_handle)
	return param.QCount()
}

//export GetBfvP
func GetBfvP(parameter_handle uint64, index int) uint64 {
	param := get_object[bfv.Parameters](parameter_handle)
	return param.P()[index]
}

//export GetBfvPCount
func GetBfvPCount(parameter_handle uint64) int {
	param := get_object[bfv.Parameters](parameter_handle)
	return param.PCount()
}

//export GetBfvN
func GetBfvN(parameter_handle uint64) int {
	param := get_object[bfv.Parameters](parameter_handle)
	return param.N()
}

//export GetBfvT
func GetBfvT(parameter_handle uint64) uint64 {
	param := get_object[bfv.Parameters](parameter_handle)
	return param.T()
}

//export GetBfvContextT
func GetBfvContextT(context_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	return context.parameter.T()
}

//export GetCkksN
func GetCkksN(parameter_handle uint64) int {
	param := get_object[ckks.Parameters](parameter_handle)
	return param.N()
}

//export GetBfvMaxLevel
func GetBfvMaxLevel(parameter_handle uint64) int {
	param := get_object[bfv.Parameters](parameter_handle)
	return param.MaxLevel()
}

//export GetCkksMaxLevel
func GetCkksMaxLevel(parameter_handle uint64) int {
	param := get_object[ckks.Parameters](parameter_handle)
	return param.MaxLevel()
}

//export GetCkksP
func GetCkksP(parameter_handle uint64, index int) uint64 {
	param := get_object[ckks.Parameters](parameter_handle)
	return param.P()[index]
}

//export GetCkksPCount
func GetCkksPCount(parameter_handle uint64) int {
	param := get_object[ckks.Parameters](parameter_handle)
	return param.PCount()
}

//export GetCkksQ
func GetCkksQ(parameter_handle uint64, index int) uint64 {
	param := get_object[ckks.Parameters](parameter_handle)
	return param.Q()[index]
}

//export GetDefaultScale
func GetDefaultScale(parameter_handle uint64) float64 {
	param := get_object[ckks.Parameters](parameter_handle)
	q1 := param.Q()[1]
	log_scale := math.Round(math.Log2(float64(q1)))
	default_scale := math.Pow(2, log_scale)
	return default_scale
}

func init_bfv_context(context *BfvContext) {
	context.encoder = bfv.NewEncoder(*context.parameter)
	if context.sk != nil {
		context.decryptor = bfv.NewDecryptor(*context.parameter, context.sk)
		context.encryptor_sk = bfv.NewEncryptor(*context.parameter, context.sk)
	} else {
		context.decryptor = nil
		context.encryptor_sk = nil
	}
	if context.pk != nil {
		context.encryptor_pk = bfv.NewEncryptor(*context.parameter, context.pk)
	} else {
		context.encryptor_pk = nil
	}
	context.evaluator = bfv.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

func init_ckks_context(context *CkksContext) {
	context.encoder = ckks.NewEncoder(*context.parameter)
	if context.support_big_complex {
		context.encoder_big = ckks.NewEncoderBigComplex(*context.parameter, 128)
	}
	if context.sk != nil {
		context.decryptor = ckks.NewDecryptor(*context.parameter, context.sk)
		context.encryptor_sk = ckks.NewEncryptor(*context.parameter, context.sk)
	} else {
		context.decryptor = nil
		context.encryptor_sk = nil
	}
	if context.pk != nil {
		context.encryptor_pk = ckks.NewEncryptor(*context.parameter, context.pk)
	} else {
		context.encryptor_pk = nil
	}
	context.evaluator = ckks.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export CreateEmptyBfvContext
func CreateEmptyBfvContext(parameter_handle uint64) uint64 {
	param := get_object[bfv.Parameters](parameter_handle)
	var context BfvContext
	context.parameter = param
	context.sk = nil
	context.pk = nil
	context.rlk = nil
	context.gk = nil

	init_bfv_context(&context)

	id := insert_object(&context)
	return id
}

//export CreateRandomBfvContext
func CreateRandomBfvContext(parameter_handle uint64, level int) uint64 {
	param := get_object[bfv.Parameters](parameter_handle)
	var context BfvContext
	context.parameter = param
	context.compressed = false
	context.kgen = bfv.NewKeyGenerator(*context.parameter)
	context.sk = context.kgen.GenSecretKey()
	context.pk = context.kgen.GenPublicKey(context.sk)
	context.rlk = context.kgen.GenRelinearizationKeyLvl(context.sk, 1, level)

	init_bfv_context(&context)

	id := insert_object(&context)
	return id
}

//export CreateEmptyCkksContext
func CreateEmptyCkksContext(parameter_handle uint64, support_big_complex bool) uint64 {
	param := get_object[ckks.Parameters](parameter_handle)
	var context CkksContext
	context.support_big_complex = support_big_complex
	context.parameter = param
	context.sk = nil
	context.pk = nil
	context.rlk = nil
	context.gk = nil

	init_ckks_context(&context)

	id := insert_object(&context)
	return id
}

//export CreateRandomCkksContext
func CreateRandomCkksContext(parameter_handle uint64, level int, support_big_complex bool) uint64 {
	param := get_object[ckks.Parameters](parameter_handle)
	var context CkksContext
	context.support_big_complex = support_big_complex
	context.parameter = param
	context.kgen = ckks.NewKeyGenerator(*context.parameter)
	context.sk = context.kgen.GenSecretKey()
	context.pk = context.kgen.GenPublicKey(context.sk)
	context.rlk = context.kgen.GenRelinearizationKeyLvl(context.sk, 1, level)

	init_ckks_context(&context)

	id := insert_object(&context)
	return id
}

//export CreateRandomCkksContextWithSeed
func CreateRandomCkksContextWithSeed(parameter_handle uint64, seed *byte, support_big_complex bool) uint64 {
	param := get_object[ckks.Parameters](parameter_handle)
	var context CkksContext
	context.support_big_complex = support_big_complex
	context.parameter = param
	seed_slice := unsafe.Slice(seed, 64)
	context.kgen = ckks.NewKeyGenerator(*context.parameter)
	context.sk = context.kgen.GenSecretKeyWithSeed(seed_slice)
	context.pk = context.kgen.GenPublicKey(context.sk)
	context.rlk = context.kgen.GenRelinearizationKey(context.sk, 1)

	init_ckks_context(&context)

	id := insert_object(&context)
	return id
}

//export CreateCkksExtraLevelContext
func CreateCkksExtraLevelContext(context_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	param := context.parameter
	extra_param_literal := ckks.ParametersLiteral{
		LogN:  param.LogN(),
		Q:     param.QP(),
		P:     []uint64{},
		Sigma: rlwe.DefaultSigma,
	}
	extra_param, err := ckks.NewParametersFromLiteral(extra_param_literal)
	if err != nil {
		panic(err)
	}

	var extra_context CkksContext
	extra_context.parameter = &extra_param

	if context.sk != nil {
		levelQ, levelP := context.sk.LevelQ(), context.sk.LevelP()
		extra_context.sk = new(rlwe.SecretKey)
		extra_context.sk.Value = extra_param.RingQP().NewPoly()
		extra_context.sk.Value.Q.IsNTT = context.sk.Value.Q.IsNTT
		extra_context.sk.Value.Q.IsMForm = context.sk.Value.Q.IsMForm
		for i := 0; i < levelQ+1; i++ {
			extra_context.sk.Value.Q.Coeffs[i] = context.sk.Value.Q.Coeffs[i]
		}
		for i := 0; i < levelP+1; i++ {
			extra_context.sk.Value.Q.Coeffs[levelQ+1+i] = context.sk.Value.P.Coeffs[i]
		}
	}

	init_ckks_context(&extra_context)

	id := insert_object(&extra_context)
	return id
}

//export MakePublicBfvContext
func MakePublicBfvContext(context_handle uint64, include_pk bool, include_rlk bool, include_gk bool) uint64 {
	var context_dest BfvContext
	context_src := get_object[BfvContext](context_handle)
	context_dest.parameter = context_src.parameter
	context_dest.compressed = context_src.compressed
	context_dest.sk = nil
	if include_pk {
		context_dest.pk = context_src.pk
	} else {
		context_dest.pk = nil
	}
	if include_rlk {
		context_dest.rlk = context_src.rlk
	} else {
		context_dest.rlk = nil
	}
	if include_gk {
		context_dest.gk = context_src.gk
	} else {
		context_dest.gk = nil
	}

	if !context_src.compressed {
		context_dest.encoder = context_src.encoder.ShallowCopy()
		context_dest.encryptor_sk = nil
		if context_src.encryptor_pk != nil {
			context_dest.encryptor_pk = context_src.encryptor_pk.ShallowCopy()
		} else {
			context_dest.encryptor_pk = nil
		}
		context_dest.decryptor = nil
		if context_src.evaluator != nil {
			context_dest.evaluator = context_src.evaluator.ShallowCopy()
		} else {
			context_dest.evaluator = nil
		}
	}

	id := insert_object(&context_dest)
	return id
}

//export MakePublicCkksContext
func MakePublicCkksContext(context_handle uint64, include_pk bool, include_rlk bool, include_gk bool) uint64 {
	var context_dest CkksContext
	context_src := get_object[CkksContext](context_handle)
	context_dest.parameter = context_src.parameter
	context_dest.sk = nil
	if include_pk {
		context_dest.pk = context_src.pk
	} else {
		context_dest.pk = nil
	}
	if include_rlk {
		context_dest.rlk = context_src.rlk
	} else {
		context_dest.rlk = nil
	}
	if include_gk {
		context_dest.gk = context_src.gk
	} else {
		context_dest.gk = nil
	}

	context_dest.encoder = context_src.encoder.ShallowCopy()
	context_dest.encryptor_sk = nil
	if context_src.encryptor_pk != nil {
		context_dest.encryptor_pk = context_src.encryptor_pk.ShallowCopy()
	} else {
		context_dest.encryptor_pk = nil
	}
	context_dest.decryptor = nil
	if context_src.evaluator != nil {
		context_dest.evaluator = context_src.evaluator.ShallowCopy()
	} else {
		context_dest.evaluator = nil
	}

	id := insert_object(&context_dest)
	return id
}

//export GenerateBfvContextPublicKeys
func GenerateBfvContextPublicKeys(context_handle uint64, level int) {
	context := get_object[BfvContext](context_handle)
	context.kgen = bfv.NewKeyGenerator(*context.parameter)
	context.pk = context.kgen.GenPublicKey(context.sk)
	context.rlk = context.kgen.GenRelinearizationKeyLvl(context.sk, 1, level)

	init_bfv_context(context)
}

//export ShallowCopyBfvContext
func ShallowCopyBfvContext(context_handle uint64) uint64 {
	var context_dest BfvContext
	context_src := get_object[BfvContext](context_handle)
	context_dest.parameter = context_src.parameter
	context_dest.compressed = context_src.compressed
	context_dest.sk = context_src.sk
	context_dest.pk = context_src.pk
	context_dest.rlk = context_src.rlk
	context_dest.gk = context_src.gk

	context_dest.encoder = context_src.encoder.ShallowCopy()
	if context_src.sk != nil {
		context_dest.encryptor_sk = context_src.encryptor_sk.ShallowCopy()
		context_dest.decryptor = context_src.decryptor.ShallowCopy()
	} else {
		context_dest.encryptor_sk = nil
		context_dest.decryptor = nil
	}
	if context_src.pk != nil {
		context_dest.encryptor_pk = context_src.encryptor_pk.ShallowCopy()
	} else {
		context_dest.encryptor_pk = nil
	}
	context_dest.evaluator = context_src.evaluator.ShallowCopy()

	id := insert_object(&context_dest)
	return id
}

//export ShallowCopyCkksContext
func ShallowCopyCkksContext(context_handle uint64) uint64 {
	var context_dest CkksContext
	context_src := get_ckks_context(context_handle)
	context_dest.parameter = context_src.parameter
	context_dest.sk = context_src.sk
	context_dest.pk = context_src.pk
	context_dest.rlk = context_src.rlk
	context_dest.gk = context_src.gk

	context_dest.encoder = context_src.encoder.ShallowCopy()
	if context_src.sk != nil {
		context_dest.encryptor_sk = context_src.encryptor_sk.ShallowCopy()
		context_dest.decryptor = context_src.decryptor.ShallowCopy()
	} else {
		context_dest.encryptor_sk = nil
		context_dest.decryptor = nil
	}
	if context_src.pk != nil {
		context_dest.encryptor_pk = context_src.encryptor_pk.ShallowCopy()
	} else {
		context_dest.encryptor_pk = nil
	}
	context_dest.evaluator = context_src.evaluator.ShallowCopy()

	id := insert_object(&context_dest)
	return id
}

//export GenBfvContextRotationKeys
func GenBfvContextRotationKeys(context_handle uint64, level int) {
	context := get_object[BfvContext](context_handle)
	rots := make([]int, 2*context.parameter.LogN()-3)
	for i := 0; i < context.parameter.LogN()-1; i++ {
		rots[i] = (1 << i)
	}
	for i := 0; i < context.parameter.LogN()-2; i++ {
		rots[i+context.parameter.LogN()-1] = -1 * (1 << i)
	}

	context.gk = context.kgen.GenRotationKeysForRotationsLvl(rots, true, context.sk, level)
	context.evaluator = context.evaluator.WithKey(rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export GenBfvContextRotationKeysForRotations
func GenBfvContextRotationKeysForRotations(context_handle uint64, rots *int32, rots_length int, include_swap_rows bool, level int) {
	context := get_object[BfvContext](context_handle)
	rots_slice := unsafe.Slice((*int32)(unsafe.Pointer(rots)), rots_length)
	context.gk = context.kgen.GenRotationKeysForRotationsLvl(convert_slice(rots_slice), include_swap_rows, context.sk, level)
	context.evaluator = context.evaluator.WithKey(rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export GenCkksContextRotationKeys
func GenCkksContextRotationKeys(context_handle uint64, level int) {
	context := get_object[CkksContext](context_handle)
	rots := make([]int, 2*context.parameter.LogN()-3)
	for i := 0; i < context.parameter.LogN()-1; i++ {
		rots[i] = (1 << i)
	}
	for i := 0; i < context.parameter.LogN()-2; i++ {
		rots[i+context.parameter.LogN()-1] = -1 * (1 << i)
	}

	context.gk = context.kgen.GenRotationKeysForRotationsLvl(rots, true, context.sk, level)
	context.evaluator = context.evaluator.WithKey(rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export GenCkksContextRotationKeysForRotations
func GenCkksContextRotationKeysForRotations(context_handle uint64, rots *int32, rots_length int, include_swap_rows bool, level int) {
	context := get_object[CkksContext](context_handle)
	rots_slice := unsafe.Slice((*int32)(unsafe.Pointer(rots)), rots_length)
	context.gk = context.kgen.GenRotationKeysForRotationsLvl(convert_slice(rots_slice), include_swap_rows, context.sk, level)
	context.evaluator = context.evaluator.WithKey(rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export ExtractBfvSecretKey
func ExtractBfvSecretKey(context_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	secret_key := context.sk
	id := insert_object(secret_key)
	return id
}

//export ExtractCkksSecretKey
func ExtractCkksSecretKey(context_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	secret_key := context.sk
	id := insert_object(secret_key)
	return id
}

//export ExtractBfvPublicKey
func ExtractBfvPublicKey(context_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	public_key := context.pk
	id := insert_object(public_key)
	return id
}

//export ExtractCkksPublicKey
func ExtractCkksPublicKey(context_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	public_key := context.pk
	id := insert_object(public_key)
	return id
}

//export ExtractBfvRelinKey
func ExtractBfvRelinKey(context_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	relin_key := context.rlk
	id := insert_object(relin_key)
	return id
}

//export ExtractCkksRelinKey
func ExtractCkksRelinKey(context_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	relin_key := context.rlk
	id := insert_object(relin_key)
	return id
}

//export ExtractKeySwitchKeyFromRelinKey
func ExtractKeySwitchKeyFromRelinKey(relin_key_handle uint64) uint64 {
	rlk := get_object[rlwe.RelinearizationKey](relin_key_handle)
	ksk := rlk.Keys[0]
	id := insert_object(ksk)
	return id
}

//export ExtractKeySwitchKeyFromGaloisKey
func ExtractKeySwitchKeyFromGaloisKey(relin_key_handle uint64, k uint64, key_switch_key_handle *C.uint64_t) int {
	glk := get_object[rlwe.RotationKeySet](relin_key_handle)
	ksk, ok := glk.Keys[k]
	if !ok {
		error_message = "Galois element not contained in the rotation key set."
		return 1
	}
	*key_switch_key_handle = (C.uint64_t)(insert_object(ksk))
	return 0
}

//export ExtractBfvGaloisKey
func ExtractBfvGaloisKey(context_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	galois_key := context.gk
	id := insert_object(galois_key)
	return id
}

//export ExtractCkksGaloisKey
func ExtractCkksGaloisKey(context_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	galois_key := context.gk
	id := insert_object(galois_key)
	return id
}

//export SetBfvContextSecretKey
func SetBfvContextSecretKey(context_handle uint64, secret_key_handle uint64) {
	context := get_object[BfvContext](context_handle)
	context.sk = get_object[rlwe.SecretKey](secret_key_handle)
	context.decryptor = bfv.NewDecryptor(*context.parameter, context.sk)
}

//export SetCkksContextSecretKey
func SetCkksContextSecretKey(context_handle uint64, secret_key_handle uint64) {
	context := get_ckks_context(context_handle)
	context.sk = get_object[rlwe.SecretKey](secret_key_handle)
	context.decryptor = ckks.NewDecryptor(*context.parameter, context.sk)
}

//export SetBfvContextPublicKey
func SetBfvContextPublicKey(context_handle uint64, public_key_handle uint64) {
	context := get_object[BfvContext](context_handle)
	context.pk = get_object[rlwe.PublicKey](public_key_handle)
	context.encryptor_pk = bfv.NewEncryptor(*context.parameter, context.pk)
}

//export SetCkksContextPublicKey
func SetCkksContextPublicKey(context_handle uint64, public_key_handle uint64) {
	context := get_ckks_context(context_handle)
	context.pk = get_object[rlwe.PublicKey](public_key_handle)
	context.encryptor_pk = ckks.NewEncryptor(*context.parameter, context.pk)
}

//export SetBfvContextRelinKey
func SetBfvContextRelinKey(context_handle uint64, relin_key_handle uint64) {
	context := get_object[BfvContext](context_handle)
	context.rlk = get_object[rlwe.RelinearizationKey](relin_key_handle)
	context.evaluator = bfv.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export SetCkksContextRelinKey
func SetCkksContextRelinKey(context_handle uint64, relin_key_handle uint64) {
	context := get_ckks_context(context_handle)
	context.rlk = get_object[rlwe.RelinearizationKey](relin_key_handle)
	context.evaluator = ckks.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export SetBfvContextGaloisKey
func SetBfvContextGaloisKey(context_handle uint64, galois_key_handle uint64) {
	context := get_object[BfvContext](context_handle)
	context.gk = get_object[rlwe.RotationKeySet](galois_key_handle)
	context.evaluator = bfv.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export SetCkksContextGaloisKey
func SetCkksContextGaloisKey(context_handle uint64, galois_key_handle uint64) {
	context := get_ckks_context(context_handle)
	context.gk = get_object[rlwe.RotationKeySet](galois_key_handle)
	context.evaluator = ckks.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export GetBfvParameter
func GetBfvParameter(context_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	param := context.parameter
	id := insert_object(param)
	return id
}

//export GetCkksParameter
func GetCkksParameter(context_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	param := context.parameter
	id := insert_object(param)
	return id
}

//export NewBfvCiphertext
func NewBfvCiphertext(context_handle uint64, degree int, level int) uint64 {
	context := get_object[BfvContext](context_handle)
	param := context.parameter
	ciphertext := bfv.NewCiphertextLvl(*param, degree, level)
	id := insert_object(ciphertext)
	return id
}

//export CopyBfvCiphertext
func CopyBfvCiphertext(x_ciphertext_handle uint64) uint64 {
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	y_ciphertext := x_ciphertext.CopyNew()
	id := insert_object(y_ciphertext)
	return id
}

//export CopyBfvCiphertextTo
func CopyBfvCiphertextTo(x_ciphertext_handle uint64, y_ciphertext_handle uint64) uint64 {
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	y_ciphertext := get_object[bfv.Ciphertext](y_ciphertext_handle)
	y_ciphertext.Ciphertext.Copy(x_ciphertext.Ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export CopyCkksCiphertext
func CopyCkksCiphertext(x_ciphertext_handle uint64) uint64 {
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	y_ciphertext := x_ciphertext.CopyNew()
	id := insert_object(y_ciphertext)
	return id
}

//export CopyCkksCiphertextTo
func CopyCkksCiphertextTo(x_ciphertext_handle uint64, y_ciphertext_handle uint64) uint64 {
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	y_ciphertext := get_object[ckks.Ciphertext](y_ciphertext_handle)
	y_ciphertext.Ciphertext.Copy(x_ciphertext.Ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export CopyCkksCiphertext3To
func CopyCkksCiphertext3To(x_ciphertext_handle uint64, y_ciphertext_handle uint64) uint64 {
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	y_ciphertext := get_object[ckks.Ciphertext](y_ciphertext_handle)
	y_ciphertext.Ciphertext.Copy(x_ciphertext.Ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export ReleaseHandle
func ReleaseHandle(handle uint64) {
	delete_object(handle)
}

func serialize_data_bit_length_from_bfv_param(param *bfv.Parameters) int {
	primes := append(param.Q(), param.P()...)
	sort.Slice(primes, func(i, j int) bool { return primes[i] < primes[j] })
	return bits.Len64(primes[len(primes)-1])
}

func serialize_data_bit_length_from_ckks_param(param *ckks.Parameters) int {
	primes := append(param.Q(), param.P()...)
	sort.Slice(primes, func(i, j int) bool { return primes[i] < primes[j] })
	return bits.Len64(primes[len(primes)-1])
}

//export SerializeBfvContext
func SerializeBfvContext(context_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	context := get_object[BfvContext](context_handle)
	var data_slice []byte
	var object_data_slice []byte

	param_data, _ := context.parameter.MarshalBinary()
	data_slice = append(data_slice, byte(len(param_data)))
	data_slice = append(data_slice, param_data...)

	data_bit_length := serialize_data_bit_length_from_bfv_param(context.parameter)

	if context.sk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.sk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.sk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	if context.pk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.pk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.pk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	if context.rlk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.rlk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.rlk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	if context.gk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.gk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.gk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeBfvContext
func DeserializeBfvContext(raw_data *byte, length uint64) uint64 {
	data_slice := unsafe.Slice(raw_data, length)

	var context BfvContext
	var pt int
	var exist bool
	var object_length int

	param := new(bfv.Parameters)
	param_size := int(data_slice[pt])
	pt += 1
	param.UnmarshalBinary(data_slice[pt : pt+param_size])
	pt += param_size
	context.parameter = param
	data_bit_length := serialize_data_bit_length_from_bfv_param(context.parameter)

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.sk = bfv.NewSecretKey(*param)
		if data_bit_length <= 32 {
			object_length = context.sk.GetDataLen32(true)
			context.sk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.sk.GetDataLen64(true)
			context.sk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.sk = nil
	}

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.pk = bfv.NewPublicKey(*param)
		if data_bit_length <= 32 {
			object_length = context.pk.GetDataLen32(true)
			context.pk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.pk.GetDataLen64(true)
			context.pk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.pk = nil
	}

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.rlk = bfv.NewRelinearizationKey(*param, 1)
		if data_bit_length <= 32 {
			object_length = context.rlk.GetDataLen32(true)
			context.rlk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.rlk.GetDataLen(true)
			context.rlk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.rlk = nil
	}

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.gk = new(rlwe.RotationKeySet)
		if data_bit_length <= 32 {
			context.gk.UnmarshalBinary32(data_slice[pt:])
		} else {
			context.gk.UnmarshalBinary(data_slice[pt:])
		}
	} else {
		context.gk = nil
	}

	init_bfv_context(&context)

	id := insert_object(&context)
	return id
}

func rlwe_context_to_bytes(context *RlweContext, param *rlwe.Parameters, writer *bytes.Buffer) {
	binary.Write(writer, binary.LittleEndian, context.sk != nil)
	if context.sk != nil {
		rlwe.SecretKeyToBytes(context.sk, param, writer)
	}

	binary.Write(writer, binary.LittleEndian, context.pk != nil)
	if context.pk != nil {
		rlwe.CiphertextQPToBytes(context.pk, param, writer)
	}

	binary.Write(writer, binary.LittleEndian, context.rlk != nil)
	if context.rlk != nil {
		rlwe.RelinearizationKeyToByte(context.rlk, param, writer)
	}

	binary.Write(writer, binary.LittleEndian, context.gk != nil)
	if context.gk != nil {
		rlwe.RotationKeySetToBytes(context.gk, param, writer)
	}
}

func bytes_to_rlwe_context(reader *bytes.Reader) RlweContext {
	var context RlweContext
	var exist bool
	context.compressed = true

	binary.Read(reader, binary.LittleEndian, &exist)
	if exist {
		sk := rlwe.BytesToSecretKey(reader)
		context.sk = &sk
	} else {
		context.sk = nil
	}

	binary.Read(reader, binary.LittleEndian, &exist)
	if exist {
		pk := rlwe.BytesToCiphertextQP(reader)
		context.pk = &pk
	} else {
		context.pk = nil
	}

	binary.Read(reader, binary.LittleEndian, &exist)
	if exist {
		rlk := rlwe.BytesToRelinearizationKey(reader)
		context.rlk = &rlk
	} else {
		context.rlk = nil
	}

	binary.Read(reader, binary.LittleEndian, &exist)
	if exist {
		gk := rlwe.BytesToRotationKeySet(reader)
		context.gk = &gk
	} else {
		context.gk = nil
	}

	return context
}

func decompress_rlwe_context(context *RlweContext, param *rlwe.Parameters) {
	if !context.compressed {
		panic("Context is not compressed.")
	}

	if context.pk != nil {
		context.pk.Decompress(param)
	}

	if context.rlk != nil {
		for _, swk := range context.rlk.Keys {
			swk.Decompress(param)
		}
	}

	if context.gk != nil {
		for _, swk := range context.gk.Keys {
			swk.Decompress(param)
		}
	}

	context.compressed = false
}

//export SerializeBfvContextAdvanced
func SerializeBfvContextAdvanced(context_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	context := get_object[BfvContext](context_handle)
	var data_slice []byte
	writer := new(bytes.Buffer)

	param_data, _ := context.parameter.MarshalBinary()
	binary.Write(writer, binary.LittleEndian, uint64(len(param_data)))
	writer.Write(param_data)

	rlwe_context_to_bytes(&context.RlweContext, &context.parameter.Parameters, writer)

	data_slice = writer.Bytes()
	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeBfvContextAdvanced
func DeserializeBfvContextAdvanced(raw_data *byte, length C.uint64_t) uint64 {
	data_slice := unsafe.Slice(raw_data, length)
	var context BfvContext

	reader := bytes.NewReader(data_slice)

	param := new(bfv.Parameters)
	var param_size uint64
	binary.Read(reader, binary.LittleEndian, &param_size)
	param_data := make([]byte, param_size)
	reader.Read(param_data)
	param.UnmarshalBinary(param_data)
	context.parameter = param

	context.RlweContext = bytes_to_rlwe_context(reader)

	id := insert_object(&context)
	return id
}

//export BfvContextDecompress
func BfvContextDecompress(context_handle uint64) {
	context := get_object[BfvContext](context_handle)
	decompress_rlwe_context(&context.RlweContext, &context.parameter.Parameters)
	init_bfv_context(context)
}

//export SerializeCkksContext
func SerializeCkksContext(context_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	context := get_ckks_context(context_handle)
	var data_slice []byte
	var object_data_slice []byte

	param_data, _ := context.parameter.MarshalBinary()
	data_slice = append(data_slice, byte(len(param_data)))
	data_slice = append(data_slice, param_data...)

	data_bit_length := serialize_data_bit_length_from_ckks_param(context.parameter)

	if context.sk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.sk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.sk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	if context.pk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.pk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.pk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	if context.rlk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.rlk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.rlk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	if context.gk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length <= 32 {
			object_data_slice, _ = context.gk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.gk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export SerializeCkksSecretKey
func SerializeCkksSecretKey(context_handle uint64, data_bit_length int, raw_data **byte, length *C.uint64_t) uint64 {
	if data_bit_length != 32 && data_bit_length != 64 {
		panic("data_bit_length is neither 32 nor 64.")
	}

	context := get_ckks_context(context_handle)
	var data_slice []byte
	var object_data_slice []byte

	param_data, _ := context.parameter.MarshalBinary()
	data_slice = append(data_slice, byte(len(param_data)))
	data_slice = append(data_slice, param_data...)

	if context.sk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length == 32 {
			object_data_slice, _ = context.sk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.sk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export SerializeCkksPublicKey
func SerializeCkksPublicKey(context_handle uint64, data_bit_length int, raw_data **byte, length *C.uint64_t) uint64 {
	if data_bit_length != 32 && data_bit_length != 64 {
		panic("data_bit_length is neither 32 nor 64.")
	}

	context := get_ckks_context(context_handle)
	var data_slice []byte
	var object_data_slice []byte

	param_data, _ := context.parameter.MarshalBinary()
	data_slice = append(data_slice, byte(len(param_data)))
	data_slice = append(data_slice, param_data...)

	if context.rlk != nil {
		data_slice = append(data_slice, 1)
		if data_bit_length == 32 {
			object_data_slice, _ = context.rlk.MarshalBinary32()
		} else {
			object_data_slice, _ = context.rlk.MarshalBinary()
		}
		data_slice = append(data_slice, object_data_slice...)
	} else {
		data_slice = append(data_slice, 0)
	}

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeCkksContext
func DeserializeCkksContext(raw_data *byte, length C.uint64_t) uint64 {
	data_slice := unsafe.Slice(raw_data, length)
	var context CkksContext
	var pt int
	var exist bool
	var object_length int

	param := new(ckks.Parameters)
	param_size := int(data_slice[pt])
	pt += 1
	param.UnmarshalBinary(data_slice[pt : pt+param_size])
	pt += param_size
	context.parameter = param

	data_bit_length := serialize_data_bit_length_from_ckks_param(context.parameter)

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.sk = ckks.NewSecretKey(*param)
		if data_bit_length <= 32 {
			object_length = context.sk.GetDataLen32(true)
			context.sk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.sk.GetDataLen64(true)
			context.sk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.sk = nil
	}

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.pk = ckks.NewPublicKey(*param)
		if data_bit_length <= 32 {
			object_length = context.pk.GetDataLen32(true)
			context.pk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.pk.GetDataLen64(true)
			context.pk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.pk = nil
	}

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.rlk = ckks.NewRelinearizationKey(*param)
		if data_bit_length <= 32 {
			object_length = context.rlk.GetDataLen32(true)
			context.rlk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.rlk.GetDataLen(true)
			context.rlk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.rlk = nil
	}

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.gk = new(rlwe.RotationKeySet)
		if data_bit_length <= 32 {
			context.gk.UnmarshalBinary32(data_slice[pt:])
		} else {
			context.gk.UnmarshalBinary(data_slice[pt:])
		}

	} else {
		context.gk = nil
	}

	init_ckks_context(&context)

	id := insert_object(&context)
	return id
}

//export DeserializeCkksSecretKey
func DeserializeCkksSecretKey(raw_data *byte, length C.uint64_t, data_bit_length int) uint64 {
	if data_bit_length != 32 && data_bit_length != 64 {
		panic("data_bit_length is neither 32 nor 64.")
	}

	data_slice := unsafe.Slice(raw_data, length)
	var context CkksContext
	var pt int
	var exist bool
	var object_length int

	param := new(ckks.Parameters)
	param_size := int(data_slice[pt])
	pt += 1
	param.UnmarshalBinary(data_slice[pt : pt+param_size])
	pt += param_size
	context.parameter = param

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.sk = ckks.NewSecretKey(*param)
		if data_bit_length == 32 {
			object_length = context.sk.GetDataLen32(true)
			context.sk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.sk.GetDataLen64(true)
			context.sk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.sk = nil
	}

	context.encoder = ckks.NewEncoder(*context.parameter)
	if context.sk != nil {
		context.decryptor = ckks.NewDecryptor(*context.parameter, context.sk)
		context.encryptor_sk = ckks.NewEncryptor(*context.parameter, context.sk)
	} else {
		context.decryptor = nil
		context.encryptor_sk = nil
	}

	id := insert_object(&context)
	return id
}

//export DeserializeCkksPublicKey
func DeserializeCkksPublicKey(raw_data *byte, length C.uint64_t, data_bit_length int) uint64 {
	if data_bit_length != 32 && data_bit_length != 64 {
		panic("data_bit_length is neither 32 nor 64.")
	}

	data_slice := unsafe.Slice(raw_data, length)
	var context CkksContext
	var pt int
	var exist bool
	var object_length int

	param := new(ckks.Parameters)
	param_size := int(data_slice[pt])
	pt += 1
	param.UnmarshalBinary(data_slice[pt : pt+param_size])
	pt += param_size
	context.parameter = param

	exist = data_slice[pt] == 1
	pt += 1
	if exist {
		context.rlk = ckks.NewRelinearizationKey(*param)
		if data_bit_length == 32 {
			object_length = context.rlk.GetDataLen32(true)
			context.rlk.UnmarshalBinary32(data_slice[pt : pt+object_length])
		} else {
			object_length = context.rlk.GetDataLen(true)
			context.rlk.UnmarshalBinary(data_slice[pt : pt+object_length])
		}
		pt += object_length
	} else {
		context.rlk = nil
	}

	context.encoder = ckks.NewEncoder(*context.parameter)
	if context.sk != nil {
		context.decryptor = ckks.NewDecryptor(*context.parameter, context.sk)
		context.encryptor_sk = ckks.NewEncryptor(*context.parameter, context.sk)
	} else {
		context.decryptor = nil
		context.encryptor_sk = nil
	}

	context.evaluator = ckks.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})

	id := insert_object(&context)
	return id
}

//export SerializeCkksContextAdvanced
func SerializeCkksContextAdvanced(context_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	context := get_ckks_context(context_handle)
	var data_slice []byte
	writer := new(bytes.Buffer)

	param_data, _ := context.parameter.MarshalBinary()
	binary.Write(writer, binary.LittleEndian, uint64(len(param_data)))
	writer.Write(param_data)

	rlwe_context_to_bytes(&context.RlweContext, &context.parameter.Parameters, writer)

	data_slice = writer.Bytes()
	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeCkksContextAdvanced
func DeserializeCkksContextAdvanced(raw_data *byte, length C.uint64_t) uint64 {
	data_slice := unsafe.Slice(raw_data, length)
	var context CkksContext

	reader := bytes.NewReader(data_slice)

	param := new(ckks.Parameters)
	var param_size uint64
	binary.Read(reader, binary.LittleEndian, &param_size)
	param_data := make([]byte, param_size)
	reader.Read(param_data)
	param.UnmarshalBinary(param_data)
	context.parameter = param

	context.RlweContext = bytes_to_rlwe_context(reader)

	id := insert_object(&context)
	return id
}

//export CkksContextDecompress
func CkksContextDecompress(context_handle uint64) {
	context := get_ckks_context(context_handle)
	decompress_rlwe_context(&context.RlweContext, &context.parameter.Parameters)
	init_ckks_context(context)
}

//export SerializeBfvCiphertext
func SerializeBfvCiphertext(ciphertext_handle uint64, param_handle uint64, raw_data **byte, length *C.uint64_t, n_drop_bit_0 int, n_drop_bit_1 int) uint64 {
	param := get_object[bfv.Parameters](param_handle)

	var data_slice []byte
	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)

	data_slice = ciphertext.ToBytes(&param.Parameters, n_drop_bit_0, n_drop_bit_1)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export SerializeBfvCompressedCiphertext
func SerializeBfvCompressedCiphertext(ciphertext_handle uint64, param_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	param := get_object[bfv.Parameters](param_handle)

	var data_slice []byte
	ciphertext := get_object[bfv.CompressedCiphertext](ciphertext_handle)
	data_slice = ciphertext.ToBytes(&param.Parameters)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export SerializeCkksCiphertext
func SerializeCkksCiphertext(ciphertext_handle uint64, param_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	param := get_object[ckks.Parameters](param_handle)

	var data_slice []byte
	ciphertext := get_object[ckks.Ciphertext](ciphertext_handle)
	data_slice = ciphertext.ToBytes(&param.Parameters)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export SerializeCkksCompressedCiphertext
func SerializeCkksCompressedCiphertext(ciphertext_handle uint64, param_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	param := get_object[ckks.Parameters](param_handle)

	var data_slice []byte
	ciphertext := get_object[ckks.CompressedCiphertext](ciphertext_handle)
	data_slice = ciphertext.ToBytes(&param.Parameters)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeBfvCiphertext
func DeserializeBfvCiphertext(raw_data *byte, length C.uint64_t) uint64 {
	data_slice := unsafe.Slice(raw_data, length)
	ciphertext := new(bfv.Ciphertext)
	ciphertext.FromBytes(data_slice)

	id := insert_object(ciphertext)
	return id
}

//export DeserializeBfvCompressedCiphertext
func DeserializeBfvCompressedCiphertext(raw_data *byte, length C.uint64_t) uint64 {
	data_slice := unsafe.Slice(raw_data, length)
	ciphertext := new(bfv.CompressedCiphertext)
	ciphertext.FromBytes(data_slice)

	id := insert_object(ciphertext)
	return id
}

//export DeserializeCkksCiphertext
func DeserializeCkksCiphertext(raw_data *byte, length C.uint64_t) uint64 {
	data_slice := unsafe.Slice(raw_data, length)
	ciphertext := new(ckks.Ciphertext)
	ciphertext.FromBytes(data_slice)

	id := insert_object(ciphertext)
	return id
}

//export DeserializeCkksCompressedCiphertext
func DeserializeCkksCompressedCiphertext(raw_data *byte, length C.uint64_t) uint64 {
	data_slice := unsafe.Slice(raw_data, length)
	ciphertext := new(ckks.CompressedCiphertext)
	ciphertext.FromBytes(data_slice)

	id := insert_object(ciphertext)
	return id
}

//export GetBfvCiphertextLevel
func GetBfvCiphertextLevel(x_ciphertext_handle uint64) int {
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	level := x_ciphertext.Level()
	return level
}

//export GetBfvCiphertextCoeff
func GetBfvCiphertextCoeff(x_ciphertext_handle uint64, poly_idx int, rns_idx int, coeff_idx int) uint64 {
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	coeff := x_ciphertext.Value[poly_idx].Coeffs[rns_idx][coeff_idx]
	return coeff
}

//export GetBfvCiphertext3Level
func GetBfvCiphertext3Level(x_ciphertext_3_handle uint64) int {
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_3_handle)
	level := x_ciphertext.Level()
	return level
}

//export GetBfvPlaintextLevel
func GetBfvPlaintextLevel(x_plaintext_handle uint64) int {
	x_plaintext := get_object[bfv.Plaintext](x_plaintext_handle)
	level := x_plaintext.Level()
	return level
}

//export GetBfvPlaintextRingtLevel
func GetBfvPlaintextRingtLevel(x_plaintext_ringt_handle uint64) int {
	x_plaintext_ringt := get_object[bfv.PlaintextRingT](x_plaintext_ringt_handle)
	level := x_plaintext_ringt.Level()
	return level
}

//export GetBfvPlaintextMulLevel
func GetBfvPlaintextMulLevel(x_plaintext_mul_handle uint64) int {
	x_plaintext_mul := get_object[bfv.PlaintextMul](x_plaintext_mul_handle)
	level := x_plaintext_mul.Level()
	return level
}

//export GetCkksCiphertextLevel
func GetCkksCiphertextLevel(x_ciphertext_handle uint64) int {
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	level := x_ciphertext.Level()
	return level
}

//export GetCkksCiphertext3Level
func GetCkksCiphertext3Level(x_ciphertext_3_handle uint64) int {
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_3_handle)
	level := x_ciphertext.Level()
	return level
}

//export GetCkksPlaintextLevel
func GetCkksPlaintextLevel(x_plaintext_handle uint64) int {
	x_plaintext := get_object[ckks.Plaintext](x_plaintext_handle)
	level := x_plaintext.Level()
	return level
}

//export GetCkksPlaintextRingtLevel
func GetCkksPlaintextRingtLevel(x_plaintext_ringt_handle uint64) int {
	x_plaintext_ringt := get_object[ckks.PlaintextRingT](x_plaintext_ringt_handle)
	level := x_plaintext_ringt.Level()
	return level
}

//export GetCkksPlaintextMulLevel
func GetCkksPlaintextMulLevel(x_plaintext_mul_handle uint64) int {
	x_plaintext_mul := get_object[ckks.PlaintextMul](x_plaintext_mul_handle)
	level := x_plaintext_mul.Level()
	return level
}

//export GetKeySwitchKeyLevel
func GetKeySwitchKeyLevel(key_switch_key_handle uint64) int {
	ksk := get_object[rlwe.SwitchingKey](key_switch_key_handle)
	level := ksk.LevelQ()
	return level
}

//export GetCkksCiphertextScale
func GetCkksCiphertextScale(x_ciphertext_handle uint64) float64 {
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	scale := x_ciphertext.Scale
	return scale
}

//export SetCkksCiphertextScale
func SetCkksCiphertextScale(x_ciphertext_handle uint64, scale_in float64) float64 {
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	x_ciphertext.Scale = scale_in
	return scale_in
}

//export GetCkksPlaintextCoeff
func GetCkksPlaintextCoeff(x_plaintext_handle uint64, rns_idx int, coeff_idx int) uint64 {
	x_plaintext := get_object[ckks.Plaintext](x_plaintext_handle)
	coeff := x_plaintext.Value.Coeffs[rns_idx][coeff_idx]
	return coeff
}

//export SetCkksPlaintextCoeff
func SetCkksPlaintextCoeff(x_plaintext_handle uint64, rns_idx int, coeff_idx int, coeff uint64) {
	x_plaintext := get_object[ckks.Plaintext](x_plaintext_handle)
	x_plaintext.Value.Coeffs[rns_idx][coeff_idx] = coeff
}

//export BfvEncode
func BfvEncode(context_handle uint64, message_array *C.uint64_t, mg_len int, level int, plaintext_handle *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)

	if mg_len <= 0 || mg_len > context.parameter.N() {
		error_message = "Invalid message length."
		return 1
	}
	if level < 0 || level > context.parameter.MaxLevel() {
		error_message = "Invalid level."
		return 1
	}

	// Create a slice corresponding to the C array so that it can be indexed
	slice := unsafe.Slice((*uint64)(message_array), mg_len)
	plaintext := bfv.NewPlaintextLvl(*context.parameter, level)
	context.encoder.Encode(slice, plaintext)

	*plaintext_handle = (C.uint64_t)(insert_object(plaintext))
	return 0
}

//export BfvEncodeRingt
func BfvEncodeRingt(context_handle uint64, message_array *C.uint64_t, mg_len int, plaintext_handle *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)

	if mg_len <= 0 || mg_len > context.parameter.N() {
		error_message = "Invalid message length."
		return 1
	}

	slice := unsafe.Slice((*uint64)(message_array), mg_len)
	plaintext := bfv.NewPlaintextRingT(*context.parameter)
	context.encoder.EncodeRingT(slice, plaintext)

	*plaintext_handle = (C.uint64_t)(insert_object(plaintext))
	return 0
}

//export BfvEncodeMul
func BfvEncodeMul(context_handle uint64, message_array *C.uint64_t, mg_len int, level int) uint64 {
	context := get_object[BfvContext](context_handle)

	slice := unsafe.Slice((*uint64)(message_array), mg_len)
	plaintext_mul := context.encoder.EncodeMulNew(slice, level)

	id := insert_object(plaintext_mul)
	return id
}

//export BfvEncodeCoeffs
func BfvEncodeCoeffs(context_handle uint64, message_array *C.uint64_t, mg_len int, level int) uint64 {
	context := get_object[BfvContext](context_handle)

	slice := unsafe.Slice((*uint64)(message_array), mg_len)
	plaintext := bfv.NewPlaintextLvl(*context.parameter, level)
	context.encoder.EncodeCoeffs(slice, plaintext)

	id := insert_object(plaintext)
	return id
}

//export BfvEncodeCoeffsRingt
func BfvEncodeCoeffsRingt(context_handle uint64, message_array *C.uint64_t, mg_len int) uint64 {
	context := get_object[BfvContext](context_handle)

	slice := unsafe.Slice((*uint64)(message_array), mg_len)
	plaintext := bfv.NewPlaintextRingT(*context.parameter)
	context.encoder.EncodeCoeffsRingT(slice, plaintext)

	id := insert_object(plaintext)
	return id
}

//export BfvEncodeCoeffsMul
func BfvEncodeCoeffsMul(context_handle uint64, message_array *C.uint64_t, mg_len int, level int) uint64 {
	context := get_object[BfvContext](context_handle)

	slice := unsafe.Slice((*uint64)(message_array), mg_len)
	plaintext_ringt := bfv.NewPlaintextRingT(*context.parameter)
	context.encoder.EncodeCoeffsRingT(slice, plaintext_ringt)
	plaintext_mul := bfv.NewPlaintextMulLvl(*context.parameter, level)
	context.encoder.RingTToMul(plaintext_ringt, plaintext_mul)

	id := insert_object(plaintext_mul)
	return id
}

//export CkksEncode
func CkksEncode(context_handle uint64, message_array *C.double, mg_len int, level int, scale float64) uint64 {
	context := get_ckks_context(context_handle)

	// Create a slice corresponding to the C array so that it can be indexed
	slice := unsafe.Slice((*float64)(message_array), mg_len)
	plaintext := ckks.NewPlaintext(*context.parameter, level, scale)
	context.encoder.EncodeSlots(slice, plaintext, context.parameter.LogN()-1)

	id := insert_object(plaintext)
	return id
}

//export CkksEncodeComplex
func CkksEncodeComplex(context_handle uint64, message_array *C.double, mg_len int, level int, scale float64) uint64 {
	context := get_ckks_context(context_handle)

	// Create a slice corresponding to the C array so that it can be indexed
	slice := unsafe.Slice((*float64)(message_array), mg_len*2)
	message := make([]complex128, mg_len)
	for i := 0; i < mg_len; i++ {
		message[i] = complex(slice[i*2], slice[i*2+1])
	}
	plaintext := ckks.NewPlaintext(*context.parameter, level, scale)
	context.encoder.EncodeSlots(message, plaintext, context.parameter.LogN()-1)

	id := insert_object(plaintext)
	return id
}

//export CkksEncodeRingt
func CkksEncodeRingt(context_handle uint64, message_array *C.double, mg_len int, scale float64) uint64 {
	context := get_ckks_context(context_handle)

	slice := unsafe.Slice((*float64)(message_array), mg_len)
	plaintext := ckks.NewPlaintextRingT(*context.parameter, scale)
	context.encoder.EncodeRingT(slice, plaintext, context.parameter.LogN()-1)

	id := insert_object(plaintext)
	return id
}

//export CkksEncodeMul
func CkksEncodeMul(context_handle uint64, message_array *C.double, mg_len int, level int, scale float64) uint64 {
	context := get_ckks_context(context_handle)
	ringq := context.parameter.RingQ()

	slice := unsafe.Slice((*float64)(message_array), mg_len)
	plaintext := context.encoder.EncodeNew(slice, level, scale, context.parameter.LogSlots())
	plaintext_mul := ckks.NewPlaintextMul(*context.parameter, level, scale)
	ringq.MForm(plaintext.Value, plaintext_mul.Value)

	id := insert_object(plaintext_mul)
	return id

}

//export CkksEncodeCoeffs
func CkksEncodeCoeffs(context_handle uint64, message_array *C.double, mg_len int, level int, scale float64) uint64 {
	context := get_ckks_context(context_handle)

	slice := unsafe.Slice((*float64)(message_array), mg_len)
	plaintext := ckks.NewPlaintext(*context.parameter, level, scale)
	context.encoder.EncodeCoeffs(slice, plaintext)

	id := insert_object(plaintext)
	return id
}

//export CkksEncodeCoeffsRingt
func CkksEncodeCoeffsRingt(context_handle uint64, message_array *C.double, mg_len int, scale float64) uint64 {
	context := get_ckks_context(context_handle)

	slice := unsafe.Slice((*float64)(message_array), mg_len)
	plaintext := ckks.NewPlaintextRingT(*context.parameter, scale)
	context.encoder.EncodeCoeffsRingT(slice, plaintext, context.parameter.LogN()-1)

	id := insert_object(plaintext)
	return id
}

//export CkksEncodeCoeffsMul
func CkksEncodeCoeffsMul(context_handle uint64, message_array *C.double, mg_len int, level int, scale float64) uint64 {
	context := get_ckks_context(context_handle)
	ringq := context.parameter.RingQ()

	slice := unsafe.Slice((*float64)(message_array), mg_len)
	plaintext := ckks.NewPlaintext(*context.parameter, level, scale)
	context.encoder.EncodeCoeffs(slice, plaintext)

	plaintext_mul := ckks.NewPlaintextMul(*context.parameter, level, scale)
	ringq.MForm(plaintext.Value, plaintext_mul.Value)

	id := insert_object(plaintext_mul)
	return id

}

//export BfvDecode
func BfvDecode(context_handle uint64, plaintext_handle uint64, raw_data **C.uint64_t, length *C.uint64_t) uint64 {
	context := get_object[BfvContext](context_handle)
	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	message := context.encoder.DecodeUintNew(plaintext)

	*raw_data = (*C.uint64_t)(unsafe.Pointer(&message[0]))
	*length = (C.uint64_t)(len(message))
	id := insert_object(&message)
	return id
}

//export BfvDecodeRingt
func BfvDecodeRingt(context_handle uint64, plaintext_handle uint64, raw_data **C.uint64_t, length *C.uint64_t) uint64 {
	context := get_object[BfvContext](context_handle)
	plaintext := get_object[bfv.PlaintextRingT](plaintext_handle)
	message := context.encoder.DecodeUintNew(plaintext)

	*raw_data = (*C.uint64_t)(unsafe.Pointer(&message[0]))
	*length = (C.uint64_t)(len(message))
	id := insert_object(&message)
	return id
}

//export BfvDecodeCoeffs
func BfvDecodeCoeffs(context_handle uint64, plaintext_handle uint64, raw_data **C.uint64_t, length *C.uint64_t) uint64 {
	context := get_object[BfvContext](context_handle)
	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	message := context.encoder.DecodeCoeffsUintNew(plaintext)

	*raw_data = (*C.uint64_t)(unsafe.Pointer(&message[0]))
	*length = (C.uint64_t)(len(message))
	id := insert_object(&message)
	return id
}

//export CkksDecode
func CkksDecode(context_handle uint64, plaintext_handle uint64, raw_data **C.double, length *C.uint64_t) uint64 {
	context := get_ckks_context(context_handle)
	plaintext := get_object[ckks.Plaintext](plaintext_handle)
	message := context.encoder.DecodeSlots(plaintext, context.parameter.LogN()-1)

	*raw_data = (*C.double)(unsafe.Pointer(&message[0]))
	*length = (C.uint64_t)(len(message))
	id := insert_object(&message)
	return id
}

//export CkksDecodeCoeffs
func CkksDecodeCoeffs(context_handle uint64, plaintext_handle uint64, raw_data **C.double, length *C.uint64_t) uint64 {
	context := get_ckks_context(context_handle)
	plaintext := get_object[ckks.Plaintext](plaintext_handle)
	message := context.encoder.DecodeCoeffs(plaintext)

	*raw_data = (*C.double)(unsafe.Pointer(&message[0]))
	*length = (C.uint64_t)(len(message))
	id := insert_object(&message)
	return id
}

//export CkksRecodeBigComplex
func CkksRecodeBigComplex(context_handle uint64, plaintext_handle uint64, level int, scale float64) uint64 {
	context := get_ckks_context(context_handle)
	pt0 := get_object[ckks.Plaintext](plaintext_handle)

	message := context.encoder_big.Decode(pt0, context.parameter.LogSlots())
	pt1 := context.encoder_big.EncodeNew(message, level, scale, context.parameter.LogSlots())
	id := insert_object(&pt1)
	return id
}

//export BfvEncryptAsymmetric
func BfvEncryptAsymmetric(context_handle uint64, plaintext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	ciphertext := context.encryptor_pk.EncryptNew(plaintext)
	id := insert_object(ciphertext)
	return id
}

//export CkksEncryptAsymmetric
func CkksEncryptAsymmetric(context_handle uint64, plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	plaintext := get_object[ckks.Plaintext](plaintext_handle)
	ciphertext := context.encryptor_pk.EncryptNew(plaintext)
	id := insert_object(ciphertext)
	return id
}

//export BfvEncryptSymmetric
func BfvEncryptSymmetric(context_handle uint64, plaintext_handle uint64, ciphertext_handle *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)

	if context.sk == nil || context.encryptor_sk == nil {
		error_message = "Context does not have sk and the corresponding encryptor."
		return 1
	}

	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	ciphertext := context.encryptor_sk.EncryptNew(plaintext)
	*ciphertext_handle = (C.uint64_t)(insert_object(ciphertext))
	return 0
}

//export BfvEncryptSymmetricCompressed
func BfvEncryptSymmetricCompressed(context_handle uint64, plaintext_handle uint64, ciphertext_handle *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)

	if context.sk == nil || context.encryptor_sk == nil {
		error_message = "Context does not have sk and the corresponding encryptor."
		return 1
	}

	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	ciphertext := bfv.NewCompressedCiphertext(*context.parameter, context.parameter.N(), plaintext.Level())
	context.encryptor_sk.EncryptCompressed(plaintext, ciphertext)
	*ciphertext_handle = (C.uint64_t)(insert_object(ciphertext))
	return 0
}

//export BfvCompressedCiphertextToCiphertext
func BfvCompressedCiphertextToCiphertext(context_handle uint64, ciphertext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	ct_in := get_object[bfv.CompressedCiphertext](ciphertext_handle)
	ct_out := ct_in.ToCiphertext(*context.parameter)
	id := insert_object(ct_out)
	return id
}

//export CkksEncryptSymmetric
func CkksEncryptSymmetric(context_handle uint64, plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	plaintext := get_object[ckks.Plaintext](plaintext_handle)
	ciphertext := context.encryptor_sk.EncryptNew(plaintext)
	id := insert_object(ciphertext)
	return id
}

//export CkksEncryptSymmetricCompressed
func CkksEncryptSymmetricCompressed(context_handle uint64, plaintext_handle uint64) uint64 {
	context := get_object[CkksContext](context_handle)
	plaintext := get_object[ckks.Plaintext](plaintext_handle)
	ciphertext := ckks.NewCompressedCiphertext(*context.parameter, context.parameter.N(), plaintext.Level(), plaintext.Scale)
	context.encryptor_sk.EncryptCompressed(plaintext, ciphertext)
	id := insert_object(ciphertext)
	return id
}

//export CkksCompressedCiphertextToCiphertext
func CkksCompressedCiphertextToCiphertext(context_handle uint64, ciphertext_handle uint64) uint64 {
	context := get_object[CkksContext](context_handle)
	ct_in := get_object[ckks.CompressedCiphertext](ciphertext_handle)
	ct_out := ct_in.ToCiphertext(*context.parameter)
	id := insert_object(ct_out)
	return id
}

//export BfvDecrypt
func BfvDecrypt(context_handle uint64, ciphertext_handle uint64, plaintext_handle *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)

	if context.sk == nil || context.decryptor == nil {
		error_message = "Context does not have sk and decryptor."
		return 1
	}
	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)
	plaintext := context.decryptor.DecryptNew(ciphertext)
	*plaintext_handle = (C.uint64_t)(insert_object(plaintext))
	return 0
}

//export CkksDecrypt
func CkksDecrypt(context_handle uint64, ciphertext_handle uint64, plaintext_handle *C.uint64_t) uint64 {
	context := get_ckks_context(context_handle)

	if context.sk == nil || context.decryptor == nil {
		error_message = "Context does not have sk and decryptor."
		return 1
	}

	ciphertext := get_object[ckks.Ciphertext](ciphertext_handle)
	plaintext := context.decryptor.DecryptNew(ciphertext)
	*plaintext_handle = (C.uint64_t)(insert_object(plaintext))
	return 0
}

//export BfvPlaintextToPlaintextRingt
func BfvPlaintextToPlaintextRingt(context_handle uint64, plaintext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	plaintext_ringt := bfv.NewPlaintextRingT(*context.parameter)
	context.encoder.DecodeRingT(plaintext, plaintext_ringt)
	id := insert_object(plaintext_ringt)
	return id
}

//export BfvPlaintextRingtToPlaintextMul
func BfvPlaintextRingtToPlaintextMul(context_handle uint64, plaintext_ringt_handle uint64, level int) uint64 {
	context := get_object[BfvContext](context_handle)
	plaintext_ringt := get_object[bfv.PlaintextRingT](plaintext_ringt_handle)
	plaintext_mul := bfv.NewPlaintextMulLvl(*context.parameter, level)
	context.encoder.RingTToMul(plaintext_ringt, plaintext_mul)
	id := insert_object(plaintext_mul)
	return id
}

//export BfvPlaintextRingtToPlaintext
func BfvPlaintextRingtToPlaintext(context_handle uint64, plaintext_ringt_handle uint64, level int) uint64 {
	context := get_object[BfvContext](context_handle)
	plaintext_ringt := get_object[bfv.PlaintextRingT](plaintext_ringt_handle)
	plaintext := bfv.NewPlaintextLvl(*context.parameter, level)
	context.encoder.ScaleUp(plaintext_ringt, plaintext)
	id := insert_object(plaintext)
	return id
}

//export CkksPlaintextRingtToPlaintextMul
func CkksPlaintextRingtToPlaintextMul(context_handle uint64, plaintext_ringt_handle uint64, level int) uint64 {
	context := get_ckks_context(context_handle)
	plaintext_ringt := get_object[ckks.PlaintextRingT](plaintext_ringt_handle)
	plaintext_mul := ckks.NewPlaintextMul(*context.parameter, level, plaintext_ringt.Scale)
	context.encoder.RingTToMul(plaintext_ringt, plaintext_mul)
	id := insert_object(plaintext_mul)
	return id
}

//export CkksPlaintextRingtToPlaintext
func CkksPlaintextRingtToPlaintext(context_handle uint64, plaintext_ringt_handle uint64, level int) uint64 {
	context := get_ckks_context(context_handle)
	plaintext_ringt := get_object[ckks.PlaintextRingT](plaintext_ringt_handle)
	plaintext := ckks.NewPlaintext(*context.parameter, level, plaintext_ringt.Scale)
	context.encoder.RingTToPt(plaintext_ringt, plaintext)
	id := insert_object(plaintext)
	return id
}

//export BfvAdd
func BfvAdd(context_handle uint64, x0_ciphertext_handle uint64, x1_ciphertext_handle uint64, y_ciphertext_handle *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_ciphertext := get_object[bfv.Ciphertext](x1_ciphertext_handle)

	if x0_ciphertext.Level() != x1_ciphertext.Level() {
		error_message = "x0 and x1 have different levels."
		return 1
	}

	y_ciphertext := context.evaluator.AddNew(x0_ciphertext, x1_ciphertext)
	*y_ciphertext_handle = C.uint64_t(insert_object(y_ciphertext))
	return 0
}

//export BfvSub
func BfvSub(context_handle uint64, x0_ciphertext_handle uint64, x1_ciphertext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_ciphertext := get_object[bfv.Ciphertext](x1_ciphertext_handle)
	y_ciphertext := context.evaluator.SubNew(x0_ciphertext, x1_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvSubPlain
func BfvSubPlain(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[bfv.Plaintext](x1_plaintext_handle)
	y_ciphertext := context.evaluator.SubNew(x0_ciphertext, x1_plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvSubPlainRingt
func BfvSubPlainRingt(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext_ringt := get_object[bfv.PlaintextRingT](x1_plaintext_handle)
	y_ciphertext := context.evaluator.SubNew(x0_ciphertext, x1_plaintext_ringt)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvNegate
func BfvNegate(context_handle uint64, x0_ciphertext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	y_ciphertext := context.evaluator.NegNew(x0_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export AddInplace
func AddInplace(context_handle uint64, x0_ciphertext_handle uint64, x1_ciphertext_handle uint64) {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_ciphertext := get_object[bfv.Ciphertext](x1_ciphertext_handle)
	context.evaluator.Add(x0_ciphertext, x1_ciphertext, x0_ciphertext)
}

//export BfvAddPlain
func BfvAddPlain(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[bfv.Plaintext](x1_plaintext_handle)
	y_ciphertext := context.evaluator.AddNew(x0_ciphertext, x1_plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvAddPlainRingt
func BfvAddPlainRingt(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext_ringt := get_object[bfv.PlaintextRingT](x1_plaintext_handle)
	y_ciphertext := context.evaluator.AddNew(x0_ciphertext, x1_plaintext_ringt)
	id := insert_object(y_ciphertext)
	return id
}

//export AddPlainInplace
func AddPlainInplace(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[bfv.Plaintext](x1_plaintext_handle)
	context.evaluator.Add(x0_ciphertext, x1_plaintext, x0_ciphertext)
}

//export CkksAdd
func CkksAdd(context_handle uint64, x0_ciphertext_handle uint64, x1_ciphertext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_ciphertext := get_object[ckks.Ciphertext](x1_ciphertext_handle)
	y_ciphertext := context.evaluator.AddNew(x0_ciphertext, x1_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksAddPlain
func CkksAddPlain(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[ckks.Plaintext](x1_plaintext_handle)
	y_ciphertext := context.evaluator.AddNew(x0_ciphertext, x1_plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksSub
func CkksSub(context_handle uint64, x0_ciphertext_handle uint64, x1_ciphertext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_ciphertext := get_object[ckks.Ciphertext](x1_ciphertext_handle)
	y_ciphertext := context.evaluator.SubNew(x0_ciphertext, x1_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksSubPlain
func CkksSubPlain(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[ckks.Plaintext](x1_plaintext_handle)
	y_ciphertext := context.evaluator.SubNew(x0_ciphertext, x1_plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksAddPlainRingt
func CkksAddPlainRingt(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_plaintext_ringt := get_object[ckks.PlaintextRingT](x1_plaintext_handle)

	// Convert PlaintextRingT to Plaintext
	plaintext := ckks.NewPlaintext(*context.parameter, x0_ciphertext.Level(), x1_plaintext_ringt.Scale)
	context.encoder.RingTToPt(x1_plaintext_ringt, plaintext)

	// Perform addition
	y_ciphertext := context.evaluator.AddNew(x0_ciphertext, plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksSubPlainRingt
func CkksSubPlainRingt(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_plaintext_ringt := get_object[ckks.PlaintextRingT](x1_plaintext_handle)

	// Convert PlaintextRingT to Plaintext
	plaintext := ckks.NewPlaintext(*context.parameter, x0_ciphertext.Level(), x1_plaintext_ringt.Scale)
	context.encoder.RingTToPt(x1_plaintext_ringt, plaintext)

	// Perform subtraction
	y_ciphertext := context.evaluator.SubNew(x0_ciphertext, plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksNegate
func CkksNegate(context_handle uint64, x0_ciphertext_handle uint64) uint64 {
	context := get_object[CkksContext](context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	y_ciphertext := context.evaluator.NegNew(x0_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvMult
func BfvMult(context_handle uint64, x0_ciphertext_handle uint64, x1_ciphertext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_ciphertext := get_object[bfv.Ciphertext](x1_ciphertext_handle)
	y_ciphertext3 := context.evaluator.MulNew(x0_ciphertext, x1_ciphertext)
	id := insert_object(y_ciphertext3)
	return id
}

//export CkksMult
func CkksMult(context_handle uint64, x0_ciphertext_handle uint64, x1_ciphertext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_ciphertext := get_object[ckks.Ciphertext](x1_ciphertext_handle)
	y_ciphertext3 := context.evaluator.MulNew(x0_ciphertext, x1_ciphertext)
	id := insert_object(y_ciphertext3)
	return id
}

//export BfvMultPlain
func BfvMultPlain(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[bfv.Plaintext](x1_plaintext_handle)
	y_ciphertext := context.evaluator.MulNew(x0_ciphertext, x1_plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvMultPlainRingt
func BfvMultPlainRingt(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_ringt_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext_ringt := get_object[bfv.PlaintextRingT](x1_plaintext_ringt_handle)
	y_ciphertext := context.evaluator.MulNew(x0_ciphertext, x1_plaintext_ringt)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvMultPlainMul
func BfvMultPlainMul(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_mul_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	x1_plaintext_mul := get_object[bfv.PlaintextMul](x1_plaintext_mul_handle)
	y_ciphertext := context.evaluator.MulNew(x0_ciphertext, x1_plaintext_mul)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvMultScalar
func BfvMultScalar(context_handle uint64, x0_ciphertext_handle uint64, x1_value int64) uint64 {
	context := get_object[BfvContext](context_handle)
	x0_ciphertext := get_object[bfv.Ciphertext](x0_ciphertext_handle)
	abs_x1 := x1_value
	if abs_x1 < 0 {
		abs_x1 = -abs_x1
	}
	y_ciphertext := context.evaluator.MulScalarNew(x0_ciphertext, uint64(abs_x1))
	if x1_value < 0 {
		context.evaluator.Neg(y_ciphertext, y_ciphertext)
	}
	id := insert_object(y_ciphertext)
	return id
}

//export CkksMultPlain
func CkksMultPlain(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[ckks.Plaintext](x1_plaintext_handle)
	y_ciphertext := context.evaluator.MulNew(x0_ciphertext, x1_plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksMultPlainMul
func CkksMultPlainMul(context_handle uint64, x0_ciphertext_handle uint64, x1_plaintext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x0_ciphertext := get_object[ckks.Ciphertext](x0_ciphertext_handle)
	x1_plaintext := get_object[ckks.PlaintextMul](x1_plaintext_handle)
	y_ciphertext := context.evaluator.MulNew(x0_ciphertext, x1_plaintext)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvRelinearize
func BfvRelinearize(context_handle uint64, x_ciphertext3_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x_ciphertext3 := get_object[bfv.Ciphertext](x_ciphertext3_handle)
	x_ciphertext := context.evaluator.RelinearizeNew(x_ciphertext3)
	id := insert_object(x_ciphertext)
	return id
}

//export CkksRelinearize
func CkksRelinearize(context_handle uint64, x_ciphertext3_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x_ciphertext3 := get_object[ckks.Ciphertext](x_ciphertext3_handle)
	x_ciphertext := context.evaluator.RelinearizeNew(x_ciphertext3)
	id := insert_object(x_ciphertext)
	return id
}

//export BfvRescale
func BfvRescale(context_handle uint64, x_ciphertext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	y_ciphertext := bfv.NewCiphertextLvl(*context.parameter, x_ciphertext.Degree(), x_ciphertext.Level()-1)
	context.evaluator.Rescale(x_ciphertext, y_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksDropLevel
func CkksDropLevel(context_handle uint64, x_ciphertext_handle uint64, levels int32) uint64 {
	context := get_ckks_context(context_handle)
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	y_ciphertext := context.evaluator.DropLevelNew(x_ciphertext, int(levels))
	id := insert_object(y_ciphertext)
	return id
}

//export CkksRescale
func CkksRescale(context_handle uint64, x_ciphertext_handle uint64, min_scale float64) uint64 {
	context := get_ckks_context(context_handle)
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	y_ciphertext := ckks.NewCiphertext(*context.parameter, 1, x_ciphertext.Level()-1, 0)
	context.evaluator.Rescale(x_ciphertext, min_scale, y_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export BfvRotateColumns
func BfvRotateColumns(context_handle uint64, x_ciphertext_handle uint64, steps *int32, length int, y_ciphertext_handles *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	steps_slice := unsafe.Slice((*int32)(unsafe.Pointer(steps)), length)

	if context.gk == nil {
		error_message = "Context does not have rotation keys, please use 'gen_rotation_keys' to prepare."
		return 1
	}

	levelQ := x_ciphertext.Level()
	x_rotated_ids := unsafe.Slice((*uint64)(unsafe.Pointer(y_ciphertext_handles)), length)

	ct1_ntt_sp := make(map[int][]ringqp.Poly)
	rotated_input := make(map[int]*bfv.Ciphertext)
	for i, step := range steps_slice {
		glk_col_pos_idx, glk_col_neg_idx := get_glk_col(step)
		var sub_steps []int
		for _, idx := range glk_col_pos_idx {
			sub_steps = append(sub_steps, 1<<idx)
		}
		for _, idx := range glk_col_neg_idx {
			sub_steps = append(sub_steps, -1*(1<<idx))
		}

		sub_steps_sum := 0
		rotated_input[sub_steps_sum] = x_ciphertext

		for _, sub_step := range sub_steps {
			if _, ok1 := rotated_input[sub_steps_sum+sub_step]; !ok1 {
				if _, ok := ct1_ntt_sp[sub_steps_sum]; !ok {
					BuffDecompQP := context.evaluator.DecomposeNTTNew(levelQ, context.parameter.PCount()-1, context.parameter.PCount(), rotated_input[sub_steps_sum].Value[1])
					ct1_ntt_sp[sub_steps_sum] = BuffDecompQP
				}

				galEl := context.parameter.GaloisElementForColumnRotationBy(sub_step)
				rotated_input[sub_steps_sum+sub_step] = context.evaluator.AutomorphismHoistedNew(levelQ, rotated_input[sub_steps_sum], ct1_ntt_sp[sub_steps_sum], galEl)
			}
			sub_steps_sum += sub_step
		}
		x_rotated_ids[i] = insert_object(rotated_input[sub_steps_sum])
	}

	return 0
}

//export BfvAdvancedRotateColumns
func BfvAdvancedRotateColumns(context_handle uint64, x_ciphertext_handle uint64, steps *int32, length int, y_ciphertext_handles *C.uint64_t) int {
	context := get_object[BfvContext](context_handle)
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	steps_slice := unsafe.Slice((*int32)(unsafe.Pointer(steps)), length)
	steps_slice_int := convert_slice(steps_slice)

	if context.gk == nil {
		error_message = "Context does not have rotation keys for given steps, please use 'gen_rotation_keys_for_rotations' to prepare."
		return 1
	}

	for _, step := range steps_slice_int {
		galEl := context.parameter.GaloisElementForColumnRotationBy(step)
		_, generated := context.gk.GetRotationKey(galEl)
		if !generated {
			error_message = fmt.Sprintf("Context does not have rotation key for step %d is not prepared, please use 'gen_rotation_keys_for_rotations' to prepare.", step)
			return 1
		}
	}

	y_ciphertexts := context.evaluator.RotateHoistedNew(x_ciphertext, steps_slice_int)
	x_rotated_ids := unsafe.Slice((*uint64)(unsafe.Pointer(y_ciphertext_handles)), length)
	for i, step := range steps_slice_int {
		x_rotated_ids[i] = insert_object(y_ciphertexts[step])
	}

	return 0
}

//export BfvRotateRows
func BfvRotateRows(context_handle uint64, x_ciphertext_handle uint64) uint64 {
	context := get_object[BfvContext](context_handle)
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	y_ciphertext := context.evaluator.RotateRowsNew(x_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksRotate
func CkksRotate(context_handle uint64, x_ciphertext_handle uint64, steps *int32, length int, y_ciphertext_handles *C.uint64_t) int {
	context := get_ckks_context(context_handle)
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	steps_slice := unsafe.Slice((*int32)(unsafe.Pointer(steps)), length)

	if context.gk == nil {
		error_message = "Context does not have rotation keys, please use 'gen_rotation_keys' to prepare."
		return 1
	}

	levelQ := x_ciphertext.Level()
	x_rotated_ids := unsafe.Slice((*uint64)(unsafe.Pointer(y_ciphertext_handles)), length)

	ct1_ntt_sp := make(map[int][]ringqp.Poly)
	rotated_input := make(map[int]*ckks.Ciphertext)
	for i, step := range steps_slice {
		glk_col_pos_idx, glk_col_neg_idx := get_glk_col(step)
		var sub_steps []int
		for _, idx := range glk_col_pos_idx {
			sub_steps = append(sub_steps, 1<<idx)
		}
		for _, idx := range glk_col_neg_idx {
			sub_steps = append(sub_steps, -1*(1<<idx))
		}

		sub_steps_sum := 0
		rotated_input[sub_steps_sum] = x_ciphertext

		for _, sub_step := range sub_steps {
			if _, ok1 := rotated_input[sub_steps_sum+sub_step]; !ok1 {
				if _, ok := ct1_ntt_sp[sub_steps_sum]; !ok {
					BuffDecompQP := context.evaluator.DecomposeNTTNew(levelQ, context.parameter.PCount()-1, context.parameter.PCount(), rotated_input[sub_steps_sum].Value[1])
					ct1_ntt_sp[sub_steps_sum] = BuffDecompQP
				}

				galEl := context.parameter.GaloisElementForColumnRotationBy(sub_step)
				rotated_input[sub_steps_sum+sub_step] = context.evaluator.AutomorphismHoistedNew(levelQ, rotated_input[sub_steps_sum], ct1_ntt_sp[sub_steps_sum], galEl)
			}
			sub_steps_sum += sub_step
		}
		x_rotated_ids[i] = insert_object(rotated_input[sub_steps_sum])
	}

	return 0
}

//export CkksConjugate
func CkksConjugate(context_handle uint64, x_ciphertext_handle uint64) uint64 {
	context := get_ckks_context(context_handle)
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	y_ciphertext := context.evaluator.ConjugateNew(x_ciphertext)
	id := insert_object(y_ciphertext)
	return id
}

//export CkksAdvancedRotate
func CkksAdvancedRotate(context_handle uint64, x_ciphertext_handle uint64, steps *int32, length int, y_ciphertext_handles *C.uint64_t) int {
	context := get_ckks_context(context_handle)
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	steps_slice := unsafe.Slice((*int32)(unsafe.Pointer(steps)), length)
	steps_slice_int := convert_slice(steps_slice)

	if context.gk == nil {
		error_message = "Context does not have rotation keys, please use 'gen_rotation_keys_for_rotations' to prepare."
		return 1
	}

	for _, step := range steps_slice_int {
		galEl := context.parameter.GaloisElementForColumnRotationBy(step)
		_, generated := context.gk.GetRotationKey(galEl)
		if !generated {
			error_message = fmt.Sprintf("Context does not have rotation key for step %d is not prepared, please use 'gen_rotation_keys_for_rotations' to prepare.", step)
			return 1
		}
	}

	y_ciphertexts := context.evaluator.RotateHoistedNew(x_ciphertext, steps_slice_int)
	x_rotated_ids := unsafe.Slice((*uint64)(unsafe.Pointer(y_ciphertext_handles)), length)
	for i, step := range steps_slice_int {
		x_rotated_ids[i] = insert_object(y_ciphertexts[step])
	}
	return 0
}

//export NewCkksCiphertext
func NewCkksCiphertext(context_handle uint64, degree int, level int, scale float64) uint64 {
	context := get_ckks_context(context_handle)
	param := context.parameter
	ciphertext := ckks.NewCiphertext(*param, degree, level, scale)
	id := insert_object(ciphertext)
	return id
}

//export PrintCkksCiphertext
func PrintCkksCiphertext(x_ciphertext_handle uint64) {
	n_print_values := 4
	x_ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	poly_degree := len(x_ciphertext.Value[0].Coeffs[0])
	for i := 0; i < 2; i++ {
		for j := 0; j < x_ciphertext.Level()+1; j++ {
			fmt.Printf("%d%d: [", i, j)
			for k := 0; k < n_print_values; k++ {
				fmt.Printf("%08x, ", x_ciphertext.Value[i].Coeffs[j][k])
			}
			fmt.Printf("..., ")
			for k := 0; k < n_print_values; k++ {
				fmt.Printf("%08x, ", x_ciphertext.Value[i].Coeffs[j][poly_degree-n_print_values+k])
			}
			fmt.Printf("]\n")
		}
	}
}

//export PrintBfvCiphertext
func PrintBfvCiphertext(x_ciphertext_handle uint64) {
	n_print_values := 4
	x_ciphertext := get_object[bfv.Ciphertext](x_ciphertext_handle)
	poly_degree := len(x_ciphertext.Value[0].Coeffs[0])
	for i := 0; i < 2; i++ {
		for j := 0; j < x_ciphertext.Level()+1; j++ {
			fmt.Printf("%d%d: [", i, j)
			for k := 0; k < n_print_values; k++ {
				fmt.Printf("%08x, ", x_ciphertext.Value[i].Coeffs[j][k])
			}
			fmt.Printf("..., ")
			for k := 0; k < n_print_values; k++ {
				fmt.Printf("%08x, ", x_ciphertext.Value[i].Coeffs[j][poly_degree-n_print_values+k])
			}
			fmt.Printf("]\n")
		}
	}
}

//export PrintBfvPlaintext
func PrintBfvPlaintext(x_plaintext_handle uint64) {
	x_plaintext := get_object[bfv.Plaintext](x_plaintext_handle)
	for j := 0; j < x_plaintext.Level()+1; j++ {
		fmt.Printf("%d: [", j)
		for k := 0; k < 4; k++ {
			fmt.Printf("%08x, ", x_plaintext.Value.Coeffs[j][k])
		}
		fmt.Printf("..., ")
		for k := 0; k < 4; k++ {
			fmt.Printf("%08x, ", x_plaintext.Value.Coeffs[j][x_plaintext.Degree()-4+k])
		}
		fmt.Printf("]\n")
	}
}

//export PrintMemUsage
func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc = %v MiB", m.Alloc/1024/1024)
	fmt.Printf("\tTotalAlloc = %v MiB", m.TotalAlloc/1024/1024)
	fmt.Printf("\tSys = %v MiB", m.Sys/1024/1024)
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

//export CkksPolyEvalStepFunction
func CkksPolyEvalStepFunction(context_handle uint64, x_ciphertext_handle uint64, a float64, b float64, degree int, threshold float64) uint64 {
	// threshold = 0.2
	context := get_ckks_context(context_handle)
	evaluator := context.evaluator
	params := context.parameter
	ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	approxF := ckks.Approximate(stepFunctionN(threshold), a, b, degree)

	// Change of variable
	evaluator.MultByConst(ciphertext, 2/(b-a), ciphertext)
	evaluator.AddConst(ciphertext, (-a-b)/(b-a), ciphertext)
	if err := evaluator.Rescale(ciphertext, params.DefaultScale(), ciphertext); err != nil {
		panic(err)
	}

	// evaluate the interpolated Chebyshev interpolant on the ciphertext
	result_ciphertext, err := evaluator.EvaluatePoly(ciphertext, approxF, ciphertext.Scale)
	if err != nil {
		panic(err)
	}

	id := insert_object(result_ciphertext)
	return id
}

func sigmoid(x float64) float64 {
	return 1 / (math.Exp(-x) + 1)
}

func stepFunction(x float64) float64 {
	if x > 0.5 {
		return 1
	} else {
		return 0
	}
}

func stepFunctionN(threshold float64) func(float64) float64 {
	return func(x float64) float64 {
		if x > threshold {
			return 1.0
		} else {
			return 0.0
		}
	}
}

func get_glk_col(step int32) (glk_col_pos_idx []int, glk_col_neg_idx []int) {
	convert2naf := func(x int32) (string, string) {
		xh := x >> 1
		x3 := x + xh
		c := xh ^ x3
		n_pos := x3 & c
		n_minus := xh & c
		return strconv.FormatInt(int64(n_pos), 2), strconv.FormatInt(int64(n_minus), 2)
	}

	r_pos, r_neg := convert2naf(step)

	for idx, digit := range r_pos {
		if digit == '0' {
			continue
		}

		step_idx := len(r_pos) - idx - 1
		glk_col_pos_idx = append(glk_col_pos_idx, step_idx)
	}

	for idx, digit := range r_neg {
		if digit == '0' {
			continue
		}

		step_idx := len(r_neg) - idx - 1
		glk_col_neg_idx = append(glk_col_neg_idx, step_idx)
	}

	return
}

type CFuncPtr unsafe.Pointer // 明确表示这是C函数指针

// 将C函数指针转为Go可调用函数
func MakeDoubleFunc(fptr CFuncPtr) func(float64) float64 {
	return func(x float64) float64 {
		// 通过桥接函数调用
		return float64(C.bridge_func(
			C.Operation(fptr), // 转换函数指针类型
			C.double(x)))      // 转换参数类型
	}
}

//export PolyEvalFunction
func PolyEvalFunction(f CFuncPtr, context_handle uint64, x_ciphertext_handle uint64, left float64, right float64, degree int) uint64 {
	context := get_ckks_context(context_handle)
	param := context.parameter
	ff := MakeDoubleFunc(f)
	approxF := ckks.Approximate(ff, left, right, degree)

	ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	context.evaluator.MultByConst(ciphertext, 2/(right-left), ciphertext)
	context.evaluator.AddConst(ciphertext, (-left-right)/(right-left), ciphertext)
	context.evaluator.Rescale(ciphertext, param.DefaultScale(), ciphertext)

	// We evaluate the interpolated Chebyshev interpolant on the ciphertext
	ciphertext, err := context.evaluator.EvaluatePoly(ciphertext, approxF, ciphertext.Scale)
	if err != nil {
		panic(err)
	}
	// fmt.Println("Done... Consumed levels:", param.MaxLevel()-ciphertext.Level())
	id := insert_object(ciphertext)
	return id
}

//export PolyEvalReluFunction
func PolyEvalReluFunction(context_handle uint64, x_ciphertext_handle uint64, left float64, right float64, degree int) uint64 {
	context := get_ckks_context(context_handle)
	param := context.parameter

	// deg := 127
	approxF := ckks.Approximate(relu, left, right, degree)
	// approxG := ckks.Approximate(g, a, b, deg)

	// Map storing which polynomial has to be applied to which slot.
	// slotsIndex := make(map[int][]int)

	// idxF := make([]int, param.Slots()>>1)
	// idxG := make([]int, param.Slots()>>1)
	// for i := 0; i < param.Slots()>>1; i++ {
	// 	idxF[i] = i * 2   // Index with all even slots
	// 	idxG[i] = i*2 + 1 // Index with all odd slots
	// }

	// slotsIndex[0] = idxF // Assigns index of all even slots to poly[0] = f(x)
	// slotsIndex[1] = idxG // Assigns index of all odd slots to poly[1] = g(x)

	ciphertext := get_object[ckks.Ciphertext](x_ciphertext_handle)
	context.evaluator.MultByConst(ciphertext, 2/(right-left), ciphertext)
	context.evaluator.AddConst(ciphertext, (-left-right)/(right-left), ciphertext)

	context.evaluator.Rescale(ciphertext, param.DefaultScale(), ciphertext)

	// We evaluate the interpolated Chebyshev interpolant on the ciphertext
	// ciphertext, err := context.evaluator.EvaluatePolyVector(ciphertext, []*ckks.Polynomial{approxF, approxG}, context.encoder, slotsIndex, ciphertext.Scale)
	ciphertext, err := context.evaluator.EvaluatePoly(ciphertext, approxF, ciphertext.Scale)
	if err != nil {
		panic(err)
	}
	// fmt.Println("Done... Consumed levels:", param.MaxLevel()-ciphertext.Level())
	id := insert_object(ciphertext)
	return id
}

// 近似函数
func relu(x float64) float64 {
	// return 1 / (math.Exp(-x) + 1)
	if x > 0 {
		return x
	} else {
		return 0
	}
	// return math.Pow(x, 2)
}

func g(x float64) float64 {
	// return f(x) * (1 - f(x))
	if x > 0 {
		return x
	} else {
		return 0
	}
}

func main() {}
