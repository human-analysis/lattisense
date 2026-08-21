package main

/*
#include "../../fhe_types_v2.h"
*/
import "C"
import (
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/bfv"
	"github.com/cipherflow-fhe/lattigo/dbfv"
	"github.com/cipherflow-fhe/lattigo/drlwe"
	"github.com/cipherflow-fhe/lattigo/rlwe"
	"github.com/cipherflow-fhe/lattigo/utils"
)

type DBfvContext struct {
	sigma_smudging float64
	*BfvContext
	crs *utils.KeyedPRNG
}

type CKGContext struct {
	crp drlwe.CKGCRP
	*dbfv.CKGProtocol
	*DBfvContext
}

type RKGContext struct {
	crp drlwe.RKGCRP
	*dbfv.RKGProtocol
	*DBfvContext
}

type RTGContext struct {
	crp drlwe.RTGCRP
	*dbfv.RTGProtocol
	*DBfvContext
}

type E2SContext struct {
	crp drlwe.CKSCRP
	*dbfv.E2SProtocol
	*DBfvContext
}

type S2EContext struct {
	crp drlwe.CKSCRP
	*dbfv.S2EProtocol
	*DBfvContext
}

type RefreshContext struct {
	crp drlwe.CKSCRP
	*dbfv.RefreshProtocol
	*DBfvContext
}

type RefreshAndPermuteContext struct {
	crp drlwe.CKSCRP
	*dbfv.MaskedTransformProtocol
	*DBfvContext
}

//export CreateRandomDBfvContext
func CreateRandomDBfvContext(context_handle uint64, crs_seed *byte, sigma_smudging float64) uint64 {
	bfv_context := get_object[BfvContext](context_handle)

	bfv_context.kgen = bfv.NewKeyGenerator(*bfv_context.parameter)
	bfv_context.sk = bfv_context.kgen.GenSecretKey()

	var context DBfvContext

	context.sigma_smudging = sigma_smudging
	context.BfvContext = bfv_context

	seed_slice := unsafe.Slice(crs_seed, 16)
	context.crs, _ = utils.NewKeyedPRNG(seed_slice)

	id := insert_object(&context)
	return id
}

//export GetDBfvBfvContext
func GetDBfvBfvContext(context_handle uint64) uint64 {
	context := get_object[DBfvContext](context_handle)
	id := insert_object(context.BfvContext)
	return id
}

//export CreateCKGContext
func CreateCKGContext(context_handle uint64) uint64 {
	dbfv_context := get_object[DBfvContext](context_handle)

	var context CKGContext
	context.DBfvContext = dbfv_context
	context.CKGProtocol = dbfv.NewCKGProtocol(*context.parameter)
	context.crp = context.SampleCRP(context.crs)

	id := insert_object(&context)
	return id
}

//export GenDBfvPublicKeyShare
func GenDBfvPublicKeyShare(context_handle uint64) uint64 {
	context := get_object[CKGContext](context_handle)

	pk_share := context.AllocateShare()
	context.GenShare(context.sk, context.crp, pk_share)

	id := insert_object(pk_share)
	return id
}

//export AggregateDBfvPublicKeyShare
func AggregateDBfvPublicKeyShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	context := get_object[CKGContext](context_handle)
	x0_share := get_object[drlwe.CKGShare](x0_share_handle)
	x1_share := get_object[drlwe.CKGShare](x1_share_handle)

	y_share := context.AllocateShare()
	context.AggregateShare(x0_share, x1_share, y_share)

	id := insert_object(y_share)
	return id
}

//export SetDBfvPublicKey
func SetDBfvPublicKey(context_handle uint64, share_handle uint64) {
	context := get_object[CKGContext](context_handle)
	pk_share := get_object[drlwe.CKGShare](share_handle)

	context.pk = bfv.NewPublicKey(*context.parameter)
	context.GenPublicKey(pk_share, context.crp, context.pk)

	context.encryptor_pk = bfv.NewEncryptor(*context.parameter, context.pk)
}

//export SerializeDBfvPublicKeyShare
func SerializeDBfvPublicKeyShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	pk_share := get_object[drlwe.CKGShare](share_handle)

	var data_slice []byte
	var object_data_slice []byte

	object_data_slice, _ = pk_share.MarshalBinary()
	data_slice = append(data_slice, object_data_slice...)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeDBfvPublicKeyShare
func DeserializeDBfvPublicKeyShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[CKGContext](context_handle)
	data_slices := unsafe.Slice(raw_data, length)
	pk_share := context.AllocateShare()
	pk_share.UnmarshalBinary(data_slices)

	id := insert_object(pk_share)
	return id
}

//export CreateE2SContext
func CreateE2SContext(context_handle uint64) uint64 {
	dbfv_context := get_object[DBfvContext](context_handle)
	var context E2SContext
	context.DBfvContext = dbfv_context
	context.E2SProtocol = dbfv.NewE2SProtocol(*context.parameter, context.sigma_smudging)
	context.crp = context.SampleCRP(context.parameter.MaxLevel(), context.crs)
	id := insert_object(&context)
	return id
}

//export GenDBfvE2SPublicAndSecretShare
func GenDBfvE2SPublicAndSecretShare(context_handle uint64, ciphertext_handle uint64, secret_share_handle *C.uint64_t) uint64 {
	context := get_object[E2SContext](context_handle)
	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)

	public_share := context.AllocateShare()
	secret_share := rlwe.NewAdditiveShare(context.parameter.Parameters)
	context.GenShare(context.sk, ciphertext.Value[1], secret_share, public_share)

	*secret_share_handle = (C.uint64_t)(insert_object(secret_share))
	id := insert_object(public_share)
	return id
}

//export AggregateDBfvE2SCKSShare
func AggregateDBfvE2SCKSShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	context := get_object[E2SContext](context_handle)

	x0_share := get_object[drlwe.CKSShare](x0_share_handle)
	x1_share := get_object[drlwe.CKSShare](x1_share_handle)

	y_share := context.AllocateShare()
	context.AggregateShare(x0_share, x1_share, y_share)

	id := insert_object(y_share)
	return id
}

//export GetDBfvE2SSecretShare
func GetDBfvE2SSecretShare(context_handle uint64, ciphertext_handle uint64, public_share_handle uint64, secret_share_handle uint64) uint64 {
	context := get_object[E2SContext](context_handle)
	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)

	public_share := get_object[drlwe.CKSShare](public_share_handle)
	secret_share := get_object[rlwe.AdditiveShare](secret_share_handle)

	secret_share_out := rlwe.NewAdditiveShare(context.parameter.Parameters)
	context.GetShare(secret_share, public_share, ciphertext, secret_share_out)

	id := insert_object(secret_share_out)
	return id
}

//export AggregateDBfvAdditiveShare
func AggregateDBfvAdditiveShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	context := get_object[DBfvContext](context_handle)

	x0_share := get_object[rlwe.AdditiveShare](x0_share_handle)
	x1_share := get_object[rlwe.AdditiveShare](x1_share_handle)
	y_share := rlwe.NewAdditiveShare(context.parameter.Parameters)
	context.parameter.RingT().Add(&x0_share.Value, &x1_share.Value, &y_share.Value)

	id := insert_object(y_share)
	return id
}

//export SetDBfvE2SPlaintextRingT
func SetDBfvE2SPlaintextRingT(context_handle uint64, secret_share_handle uint64) uint64 {
	context := get_object[DBfvContext](context_handle)
	secret_share := get_object[rlwe.AdditiveShare](secret_share_handle)

	plaintext := bfv.NewPlaintextRingT(*context.parameter)
	plaintext.Value.Copy(&secret_share.Value)

	id := insert_object(plaintext)
	return id
}

//export SerializeDBfvCKSShare
func SerializeDBfvCKSShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	public_share := get_object[drlwe.CKSShare](share_handle)

	var data_slice []byte
	var object_data_slice []byte

	object_data_slice, _ = public_share.MarshalBinary()
	data_slice = append(data_slice, object_data_slice...)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)

	return id
}

//export DeserializeDBfvE2SCKSShare
func DeserializeDBfvE2SCKSShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[E2SContext](context_handle)

	data_slices := unsafe.Slice(raw_data, length)

	public_share := context.AllocateShare()
	public_share.UnmarshalBinary(data_slices)

	id := insert_object(public_share)
	return id
}

//export SerializeDBfvAdditiveShare
func SerializeDBfvAdditiveShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	secret_share := get_object[rlwe.AdditiveShare](share_handle)

	var data_slice []byte
	var object_data_slice []byte
	object_data_slice, _ = secret_share.Value.MarshalBinary()
	data_slice = append(data_slice, object_data_slice...)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeDBfvAdditiveShare
func DeserializeDBfvAdditiveShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[DBfvContext](context_handle)

	data_slices := unsafe.Slice(raw_data, length)
	secret_share := rlwe.NewAdditiveShare(context.parameter.Parameters)
	secret_share.Value.UnmarshalBinary(data_slices)

	id := insert_object(secret_share)
	return id
}

//export CreateS2EContext
func CreateS2EContext(context_handle uint64) uint64 {
	dbfv_context := get_object[DBfvContext](context_handle)
	var context S2EContext
	context.DBfvContext = dbfv_context
	context.S2EProtocol = dbfv.NewS2EProtocol(*context.parameter, context.sigma_smudging)
	context.crp = context.SampleCRP(context.parameter.MaxLevel(), context.crs)
	id := insert_object(&context)
	return id
}

//export GenDBfvS2EPublicShare
func GenDBfvS2EPublicShare(context_handle uint64, secret_share_handle uint64) uint64 {
	context := get_object[S2EContext](context_handle)

	secret_share := get_object[rlwe.AdditiveShare](secret_share_handle)
	public_share := context.AllocateShare()

	context.GenShare(context.sk, context.crp, secret_share, public_share)

	id := insert_object(public_share)
	return id
}

//export AggregateDBfvS2ECKSShare
func AggregateDBfvS2ECKSShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	context := get_object[S2EContext](context_handle)

	x0_share := get_object[drlwe.CKSShare](x0_share_handle)
	x1_share := get_object[drlwe.CKSShare](x1_share_handle)

	y_share := context.AllocateShare()
	context.AggregateShare(x0_share, x1_share, y_share)

	id := insert_object(y_share)
	return id
}

//export SetDBfvS2ECiphertext
func SetDBfvS2ECiphertext(context_handle uint64, public_share_handle uint64) uint64 {
	context := get_object[S2EContext](context_handle)

	public_share := get_object[drlwe.CKSShare](public_share_handle)
	ct := bfv.NewCiphertext(*context.parameter, 1)
	context.GetEncryption(public_share, context.crp, ct)

	id := insert_object(ct)
	return id
}

//export DeserializeDBfvS2ECKSShare
func DeserializeDBfvS2ECKSShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[S2EContext](context_handle)

	data_slices := unsafe.Slice(raw_data, length)

	public_share := context.AllocateShare()
	public_share.UnmarshalBinary(data_slices)

	id := insert_object(public_share)
	return id
}

//export CreateRKGContext
func CreateRKGContext(context_handle uint64) uint64 {
	dbfv_context := get_object[DBfvContext](context_handle)
	var context RKGContext
	context.DBfvContext = dbfv_context
	context.RKGProtocol = dbfv.NewRKGProtocol(*context.parameter)
	context.crp = context.SampleCRP(context.crs)
	id := insert_object(&context)
	return id
}

//export GenDBfvRelinKeyShareRoundOne
func GenDBfvRelinKeyShareRoundOne(context_handle uint64, eph_sk_handle *C.uint64_t) uint64 {
	context := get_object[RKGContext](context_handle)

	eph_sk, share1, _ := context.AllocateShare()
	context.GenShareRoundOne(context.sk, context.crp, eph_sk, share1)

	*eph_sk_handle = (C.uint64_t)(insert_object(eph_sk))
	id := insert_object(share1)
	return id
}

//export AggregateDBfvRelinKeyShare
func AggregateDBfvRelinKeyShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	context := get_object[RKGContext](context_handle)

	x0_share := get_object[drlwe.RKGShare](x0_share_handle)
	x1_share := get_object[drlwe.RKGShare](x1_share_handle)
	_, y_share, _ := context.AllocateShare()

	context.AggregateShare(x0_share, x1_share, y_share)

	id := insert_object(y_share)
	return id
}

//export GenDBfvRelinKeyShareRoundTwo
func GenDBfvRelinKeyShareRoundTwo(context_handle uint64, eph_sk_handle uint64, share1_handle uint64) uint64 {
	context := get_object[RKGContext](context_handle)

	eph_sk := get_object[rlwe.SecretKey](eph_sk_handle)
	share1 := get_object[drlwe.RKGShare](share1_handle)
	_, _, share2 := context.AllocateShare()

	context.GenShareRoundTwo(eph_sk, context.sk, share1, share2)

	id := insert_object(share2)
	return id
}

//export SetDBfvRelinKey
func SetDBfvRelinKey(context_handle uint64, share1_handle uint64, share2_handle uint64) {
	context := get_object[RKGContext](context_handle)
	context.rlk = bfv.NewRelinearizationKey(*context.parameter, 1)

	share1 := get_object[drlwe.RKGShare](share1_handle)
	share2 := get_object[drlwe.RKGShare](share2_handle)

	context.GenRelinearizationKey(share1, share2, context.rlk)

	context.evaluator = bfv.NewEvaluator(*context.parameter, rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: nil,
	})
}

//export SerializeDBfvRelinKeyShare
func SerializeDBfvRelinKeyShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	share := get_object[drlwe.RKGShare](share_handle)

	var data_slice []byte
	var object_data_slice []byte

	object_data_slice, _ = share.MarshalBinary()
	data_slice = append(data_slice, object_data_slice...)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeDBfvRelinKeyShare
func DeserializeDBfvRelinKeyShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[RKGContext](context_handle)
	data_slices := unsafe.Slice(raw_data, length)

	_, share, _ := context.AllocateShare()
	share.UnmarshalBinary(data_slices)

	id := insert_object(share)
	return id
}

//export CreateRTGContext
func CreateRTGContext(context_handle uint64) uint64 {
	dbfv_context := get_object[DBfvContext](context_handle)
	var context RTGContext
	context.DBfvContext = dbfv_context
	context.RTGProtocol = dbfv.NewRotKGProtocol(*context.parameter)
	context.crp = context.SampleCRP(context.crs)
	id := insert_object(&context)
	return id
}

//export GenDBfvGaloisKeyShare
func GenDBfvGaloisKeyShare(context_handle uint64, rots *int32, rots_length int, include_swap_rows bool, share_handles *C.uint64_t) int {
	context := get_object[RTGContext](context_handle)

	rots_slice := unsafe.Slice((*int32)(unsafe.Pointer(rots)), rots_length)
	galEls := make([]uint64, len(rots_slice), len(rots_slice)+1)
	for i, k := range rots_slice {
		galEls[i] = context.parameter.GaloisElementForColumnRotationBy(int(k))
	}
	if include_swap_rows {
		galEls = append(galEls, context.parameter.GaloisElementForRowRotation())
	}

	shares := make([]*drlwe.RTGShare, len(galEls))
	for i, galEl := range galEls {
		shares[i] = context.AllocateShare()
		context.GenShare(context.sk, galEl, context.crp, shares[i])
	}

	ids := unsafe.Slice((*uint64)(unsafe.Pointer(share_handles)), len(galEls))
	for i := range galEls {
		ids[i] = insert_object(shares[i])
	}

	return 0
}

//export AggregateDBfvGaloisKeyShare
func AggregateDBfvGaloisKeyShare(context_handle uint64, x0_share_handles *C.uint64_t, x1_share_handles *C.uint64_t, length int, y_share_handles *C.uint64_t) int {
	context := get_object[RTGContext](context_handle)
	x0_share_handles_slice := unsafe.Slice((*uint64)(x0_share_handles), length)
	x1_share_handles_slice := unsafe.Slice((*uint64)(x1_share_handles), length)
	y_share_handles_slice := unsafe.Slice((*uint64)(unsafe.Pointer(y_share_handles)), length)

	x0_shares := make([]*drlwe.RTGShare, length)
	x1_shares := make([]*drlwe.RTGShare, length)
	y_shares := make([]*drlwe.RTGShare, length)

	for i := range x0_share_handles_slice {
		x0_shares[i] = get_object[drlwe.RTGShare](x0_share_handles_slice[i])
		x1_shares[i] = get_object[drlwe.RTGShare](x1_share_handles_slice[i])
		y_shares[i] = context.AllocateShare()

		context.AggregateShare(x0_shares[i], x1_shares[i], y_shares[i])
		y_share_handles_slice[i] = insert_object(y_shares[i])
	}

	return 0
}

//export SetDBfvRotationKey
func SetDBfvRotationKey(context_handle uint64, rots *int32, rots_length int, include_swap_rows bool, share_handles *C.uint64_t) {
	context := get_object[RTGContext](context_handle)

	rots_slice := unsafe.Slice((*int32)(unsafe.Pointer(rots)), rots_length)

	galEls := make([]uint64, len(rots_slice), len(rots_slice)+1)
	for i, k := range rots_slice {
		galEls[i] = context.parameter.GaloisElementForColumnRotationBy(int(k))
	}
	if include_swap_rows {
		galEls = append(galEls, context.parameter.GaloisElementForRowRotation())
	}

	context.gk = bfv.NewRotationKeySet(*context.parameter, galEls)

	share_handles_slice := unsafe.Slice((*uint64)(share_handles), len(galEls))
	shares := make([]*drlwe.RTGShare, len(galEls))
	for i := range shares {
		shares[i] = get_object[drlwe.RTGShare](share_handles_slice[i])
	}

	for i, galEl := range galEls {
		context.GenRotationKey(shares[i], context.crp, context.gk.Keys[galEl])
	}

	context.evaluator = context.evaluator.WithKey(rlwe.EvaluationKey{
		Rlk:  context.rlk,
		Rtks: context.gk,
	})
}

//export SerializeDBfvGaloisKeyShare
func SerializeDBfvGaloisKeyShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	share := get_object[drlwe.RTGShare](share_handle)

	var data_slice []byte
	var object_data_slice []byte

	object_data_slice, _ = share.MarshalBinary()
	data_slice = append(data_slice, object_data_slice...)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeDBfvGaloisKeyShare
func DeserializeDBfvGaloisKeyShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[RTGContext](context_handle)
	data_slices := unsafe.Slice(raw_data, length)

	share := context.AllocateShare()
	share.UnmarshalBinary(data_slices)

	id := insert_object(share)
	return id
}

//export CreateRefreshContext
func CreateRefreshContext(context_handle uint64) uint64 {
	dbfv_context := get_object[DBfvContext](context_handle)

	var context RefreshContext
	context.DBfvContext = dbfv_context
	context.RefreshProtocol = dbfv.NewRefreshProtocol(*context.parameter, context.sigma_smudging)
	context.crp = context.SampleCRP(context.parameter.MaxLevel(), context.crs)
	id := insert_object(&context)
	return id
}

//export GenDBfvRefreshShare
func GenDBfvRefreshShare(context_handle uint64, ciphertext_handle uint64) uint64 {
	context := get_object[RefreshContext](context_handle)

	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)

	share := context.AllocateShare()
	context.GenShare(context.sk, ciphertext.Value[1], context.crp, share)

	id := insert_object(share)
	return id
}

//export AggregateDBfvRefreshShare
func AggregateDBfvRefreshShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	context := get_object[RefreshContext](context_handle)

	x0_share := get_object[dbfv.RefreshShare](x0_share_handle)
	x1_share := get_object[dbfv.RefreshShare](x1_share_handle)

	y_share := context.AllocateShare()
	context.AggregateShare(x0_share, x1_share, y_share)

	id := insert_object(y_share)
	return id
}

//export DBfvRefreshFinalize
func DBfvRefreshFinalize(context_handle uint64, ciphertext_handle uint64, share_handle uint64) uint64 {
	context := get_object[RefreshContext](context_handle)

	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)
	share := get_object[dbfv.RefreshShare](share_handle)

	ct := bfv.NewCiphertext(*context.parameter, 1)
	context.Finalize(ciphertext, context.crp, share, ct)

	id := insert_object(ct)
	return id
}

//export SerializeDBfvRefreshShare
func SerializeDBfvRefreshShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	share := get_object[dbfv.RefreshShare](share_handle)

	var data_slice []byte
	var object_data_slice []byte

	object_data_slice, _ = share.MarshalBinary()
	data_slice = append(data_slice, object_data_slice...)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeDBfvRefreshShare
func DeserializeDBfvRefreshShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[RefreshContext](context_handle)
	data_slices := unsafe.Slice(raw_data, length)

	share := context.AllocateShare()
	share.UnmarshalBinary(data_slices)

	id := insert_object(share)
	return id
}

//export CreateRefreshAndPermuteContext
func CreateRefreshAndPermuteContext(context_handle uint64) uint64 {
	dbfv_context := get_object[DBfvContext](context_handle)

	var context RefreshAndPermuteContext
	context.DBfvContext = dbfv_context
	context.MaskedTransformProtocol = dbfv.NewMaskedTransformProtocol(*context.parameter, context.sigma_smudging)
	context.crp = context.SampleCRP(dbfv_context.parameter.MaxLevel(), context.crs)

	id := insert_object(&context)
	return id
}

//export GenDBfvRefreshAndPermuteShare
func GenDBfvRefreshAndPermuteShare(context_handle uint64, ciphertext_handle uint64, permute *C.uint64_t) uint64 {
	context := get_object[RefreshAndPermuteContext](context_handle)
	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)

	permute_slice := unsafe.Slice((*uint64)(unsafe.Pointer(permute)), context.parameter.N())
	permute_func := func(coeffs []uint64) {
		coeffsPerm := make([]uint64, len(coeffs))
		for i := range coeffs {
			coeffsPerm[i] = coeffs[permute_slice[i]]
		}
		copy(coeffs, coeffsPerm)
	}

	share := context.AllocateShare()
	context.GenShare(context.sk, ciphertext.Value[1], context.crp, permute_func, share)

	id := insert_object(share)
	return id
}

//export AggregateDBfvRefreshAndPermuteShare
func AggregateDBfvRefreshAndPermuteShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	context := get_object[RefreshAndPermuteContext](context_handle)

	x0_share := get_object[dbfv.MaskedTransformShare](x0_share_handle)
	x1_share := get_object[dbfv.MaskedTransformShare](x1_share_handle)

	y_share := context.AllocateShare()

	context.AggregateShare(x0_share, x1_share, y_share)

	id := insert_object(y_share)
	return id
}

//export DBfvRefreshAndPermuteTransform
func DBfvRefreshAndPermuteTransform(context_handle uint64, ciphertext_handle uint64, permute *C.uint64_t, share_handle uint64) uint64 {
	context := get_object[RefreshAndPermuteContext](context_handle)

	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)
	share := get_object[dbfv.MaskedTransformShare](share_handle)

	permute_slice := unsafe.Slice((*uint64)(unsafe.Pointer(permute)), context.parameter.N())
	permute_func := func(coeffs []uint64) {
		coeffsPerm := make([]uint64, len(coeffs))
		for i := range coeffs {
			coeffsPerm[i] = coeffs[permute_slice[i]]
		}
		copy(coeffs, coeffsPerm)
	}

	ct := bfv.NewCiphertext(*context.parameter, 1)
	context.Transform(ciphertext, permute_func, context.crp, share, ct)

	id := insert_object(ct)
	return id
}

//export SerializeDBfvRefreshAndPermuteShare
func SerializeDBfvRefreshAndPermuteShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	share := get_object[dbfv.MaskedTransformShare](share_handle)

	var data_slice []byte
	var object_data_slice []byte

	object_data_slice, _ = share.MarshalBinary()
	data_slice = append(data_slice, object_data_slice...)

	*raw_data = (*byte)(unsafe.Pointer(&data_slice[0]))
	*length = (C.uint64_t)(len(data_slice))
	id := insert_object(&data_slice)
	return id
}

//export DeserializeDBfvvRefreshAndPermuteShare
func DeserializeDBfvvRefreshAndPermuteShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	context := get_object[RefreshAndPermuteContext](context_handle)

	data_slices := unsafe.Slice(raw_data, length)
	pk_share := context.AllocateShare()
	pk_share.UnmarshalBinary(data_slices)

	id := insert_object(pk_share)
	return id
}
