/*
 * Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file gpu_abi_bridge_executors.h
 * @brief ABI layer ↔ GPU backend bridge executors for heterogeneous computing
 *
 * This module provides ABI bridge executors between ABI layer (C struct types)
 * and GPU backend types (heongpu types):
 * - LOAD_TO_BACKEND: C struct (CCiphertext/CPlaintext/etc.) → GPU types (heongpu::Ciphertext/Plaintext/etc.)
 * - STORE_FROM_BACKEND: GPU types → C struct
 *
 * These executors handle data transfer for GPU acceleration.
 */

#ifndef GPU_ABI_BRIDGE_EXECUTORS_H
#define GPU_ABI_BRIDGE_EXECUTORS_H

#include "../mega_ag.h"
#include "../cpu_task_utils.h"
#include <memory>
#include <stdexcept>
#include <any>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <heongpu/heongpu.hpp>

extern "C" {
#include "../../abi/c_types.h"
#include "../../abi/c_structs.h"
}

/**
 * @brief Check CUDA error and throw exception if error occurred
 */
inline void CHECK(cudaError_t err) {
    if (err != cudaSuccess) {
        throw std::runtime_error(cudaGetErrorString(err));
    }
}

struct GpuPinnedH2DStats {
    std::atomic<uint64_t> staged_objects{0};
    std::atomic<uint64_t> staged_bytes{0};
    std::atomic<uint64_t> original_segments{0};
    std::atomic<uint64_t> allocation_count{0};
    std::atomic<uint64_t> allocation_bytes{0};
    std::atomic<uint64_t> allocation_failures{0};
    std::atomic<uint64_t> packing_nanoseconds{0};
    std::atomic<uint64_t> fallback_count{0};
};

/**
 * Request-scoped, stream-local pinned staging storage for plaintext/ciphertext
 * H2D transfers. The completion event prevents reuse while CUDA still reads
 * the preceding staged object.
 */
class GpuPinnedH2DStaging {
  public:
    explicit GpuPinnedH2DStaging(GpuPinnedH2DStats& stats) : stats_(stats) {}

    GpuPinnedH2DStaging(const GpuPinnedH2DStaging&) = delete;
    GpuPinnedH2DStaging& operator=(const GpuPinnedH2DStaging&) = delete;

    ~GpuPinnedH2DStaging() {
        finish_pending();
        release_buffer();
        if (completion_event_ != nullptr) {
            cudaEventDestroy(completion_event_);
        }
    }

    bool copy_segments(void* destination,
                       const std::vector<std::pair<const void*, size_t>>& segments,
                       cudaStream_t stream) {
        size_t total_bytes = 0;
        for (const auto& segment : segments) {
            total_bytes += segment.second;
        }
        if (total_bytes == 0) {
            return true;
        }

        if (!ensure_capacity(total_bytes)) {
            stats_.fallback_count.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        finish_pending();

        const auto pack_start = std::chrono::steady_clock::now();
        auto* cursor = static_cast<unsigned char*>(buffer_);
        for (const auto& segment : segments) {
            std::memcpy(cursor, segment.first, segment.second);
            cursor += segment.second;
        }
        const auto pack_end = std::chrono::steady_clock::now();

        CHECK(cudaMemcpyAsync(destination, buffer_, total_bytes, cudaMemcpyHostToDevice, stream));
        if (completion_event_ == nullptr) {
            CHECK(cudaEventCreateWithFlags(&completion_event_, cudaEventDisableTiming));
        }
        CHECK(cudaEventRecord(completion_event_, stream));
        pending_ = true;

        stats_.staged_objects.fetch_add(1, std::memory_order_relaxed);
        stats_.staged_bytes.fetch_add(total_bytes, std::memory_order_relaxed);
        stats_.original_segments.fetch_add(segments.size(), std::memory_order_relaxed);
        stats_.packing_nanoseconds.fetch_add(
            std::chrono::duration_cast<std::chrono::nanoseconds>(pack_end - pack_start).count(),
            std::memory_order_relaxed);
        return true;
    }

  private:
    bool ensure_capacity(size_t required_bytes) {
        if (required_bytes <= capacity_) {
            return true;
        }
        finish_pending();
        release_buffer();

        void* new_buffer = nullptr;
        const cudaError_t status = cudaHostAlloc(&new_buffer, required_bytes, cudaHostAllocDefault);
        if (status != cudaSuccess) {
            stats_.allocation_failures.fetch_add(1, std::memory_order_relaxed);
            cudaGetLastError();
            return false;
        }
        buffer_ = new_buffer;
        capacity_ = required_bytes;
        stats_.allocation_count.fetch_add(1, std::memory_order_relaxed);
        stats_.allocation_bytes.fetch_add(required_bytes, std::memory_order_relaxed);
        return true;
    }

    void finish_pending() noexcept {
        if (pending_ && completion_event_ != nullptr) {
            cudaEventSynchronize(completion_event_);
            pending_ = false;
        }
    }

    void release_buffer() noexcept {
        if (buffer_ != nullptr) {
            std::memset(buffer_, 0, capacity_);
            cudaFreeHost(buffer_);
            buffer_ = nullptr;
            capacity_ = 0;
        }
    }

    GpuPinnedH2DStats& stats_;
    void* buffer_ = nullptr;
    size_t capacity_ = 0;
    cudaEvent_t completion_event_ = nullptr;
    bool pending_ = false;
};

/**
 * @brief Export plaintext from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_plaintext(const CPlaintext& src,
                      heongpu::Plaintext<SchemeType>& dest,
                      GpuPinnedH2DStaging* staging = nullptr) {
    int N = src.poly.components->n;
    if (staging != nullptr) {
        std::vector<std::pair<const void*, size_t>> segments;
        segments.reserve(src.poly.n_component);
        for (int i = 0; i < src.poly.n_component; i++) {
            segments.emplace_back(src.poly.components[i].data, N * sizeof(uint64_t));
        }
        if (staging->copy_segments(dest.data(), segments, dest.stream())) {
            return;
        }
    }
    for (int i = 0; i < src.poly.n_component; i++) {
        CHECK(cudaMemcpyAsync(&(dest.data()[i * N]), src.poly.components[i].data, N * sizeof(uint64_t),
                              cudaMemcpyHostToDevice, dest.stream()));
    }
}

/**
 * @brief Export ciphertext from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_ciphertext(const CCiphertext& src,
                       heongpu::Ciphertext<SchemeType>& dest,
                       GpuPinnedH2DStaging* staging = nullptr) {
    int N = src.polys->components->n;
    int n_component = src.polys->n_component;
    if (staging != nullptr) {
        std::vector<std::pair<const void*, size_t>> segments;
        segments.reserve((src.degree + 1) * n_component);
        for (int i = 0; i < src.degree + 1; i++) {
            for (int j = 0; j < n_component; j++) {
                segments.emplace_back(src.polys[i].components[j].data, N * sizeof(uint64_t));
            }
        }
        if (staging->copy_segments(dest.data(), segments, dest.stream())) {
            return;
        }
    }
    for (int i = 0; i < src.degree + 1; i++) {
        for (int j = 0; j < n_component; j++) {
            CHECK(cudaMemcpyAsync(&(dest.data()[i * n_component * N + j * N]), src.polys[i].components[j].data,
                                  N * sizeof(uint64_t), cudaMemcpyHostToDevice, dest.stream()));
        }
    }
}

/**
 * @brief Export relinearization key from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_relin_key(const CRelinKey& src,
                      heongpu::Relinkey<SchemeType>& dest,
                      int first_Q_size,
                      int first_Qprime_size) {
    int N = src.public_keys->polys->components->n;
    int n_public_key = src.n_public_key;
    int level = src.public_keys->level;
    int n_component = src.public_keys->polys->n_component;

    for (int i = 0; i < n_public_key; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < n_component; k++) {
                int k_ = (k < level + 1) ? k : k - (level + 1) + first_Q_size;
                CHECK(
                    cudaMemcpyAsync(&(dest.data()[i * 2 * first_Qprime_size * N + j * first_Qprime_size * N + k_ * N]),
                                    src.public_keys[i].polys[j].components[k].data, N * sizeof(uint64_t),
                                    cudaMemcpyHostToDevice, dest.stream()));
            }
        }
    }
}

/**
 * @brief Export Galois key from C struct to GPU device memory (specific galois element)
 */
template <heongpu::Scheme SchemeType>
void export_galois_key(const CGaloisKey& src,
                       heongpu::Galoiskey<SchemeType>& dest,
                       uint32_t galois_element,
                       int first_Q_size,
                       int first_Qprime_size) {
    int N = src.key_switch_keys->public_keys->polys->components->n;
    int n_public_key = src.key_switch_keys->n_public_key;
    int level = src.key_switch_keys->public_keys->level;
    int n_component = src.key_switch_keys->public_keys->polys->n_component;
    int n_key_switch_key = src.n_key_switch_key;

    for (int i = 0; i < n_key_switch_key; i++) {
        if (src.galois_elements[i] != galois_element) {
            continue;
        }

        for (int j = 0; j < n_public_key; j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < n_component; l++) {
                    int l_ = (l < level + 1) ? l : l - (level + 1) + first_Q_size;
                    if (galois_element != 2 * N - 1) {
                        CHECK(cudaMemcpyAsync(
                            &(dest.data(
                                galois_element)[j * 2 * first_Qprime_size * N + k * first_Qprime_size * N + l_ * N]),
                            src.key_switch_keys[i].public_keys[j].polys[k].components[l].data, N * sizeof(uint64_t),
                            cudaMemcpyHostToDevice, dest.stream()));
                    } else {
                        CHECK(cudaMemcpyAsync(
                            &(dest.c_data()[j * 2 * first_Qprime_size * N + k * first_Qprime_size * N + l_ * N]),
                            src.key_switch_keys[i].public_keys[j].polys[k].components[l].data, N * sizeof(uint64_t),
                            cudaMemcpyHostToDevice, dest.stream()));
                    }
                }
            }
        }
    }
}

/**
 * @brief Export switching key from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_switching_key(const ::CKeySwitchKey& src,
                          heongpu::Switchkey<SchemeType>& dest,
                          int first_Q_size,
                          int first_Qprime_size) {
    int N = src.public_keys->polys->components->n;
    int n_public_key = src.n_public_key;
    int level = src.public_keys->level;
    int n_component = src.public_keys->polys->n_component;

    for (int i = 0; i < n_public_key; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < n_component; k++) {
                int k_ = (k < level + 1) ? k : k - (level + 1) + first_Q_size;
                CHECK(
                    cudaMemcpyAsync(&(dest.data()[i * 2 * first_Qprime_size * N + j * first_Qprime_size * N + k_ * N]),
                                    src.public_keys[i].polys[j].components[k].data, N * sizeof(uint64_t),
                                    cudaMemcpyHostToDevice, dest.stream()));
            }
        }
    }
}

struct GpuKeyCacheSnapshot {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t relin_hits = 0;
    uint64_t relin_misses = 0;
    uint64_t galois_hits = 0;
    uint64_t galois_misses = 0;
    uint64_t switch_hits = 0;
    uint64_t switch_misses = 0;
};

struct GpuKeyCacheKey {
    uint64_t task_identity = 0;
    uint64_t parameter_identity = 0;
    uint64_t evaluation_context_identity = 0;
    uint64_t evaluation_context_generation = 0;
    int gpu_device = 0;
    DataType type = TYPE_CUSTOM;
    NodeIndex source_node = 0;
    int32_t level = -1;
    int32_t sp_level = -1;
    uint32_t galois_element = 0;

    bool operator==(const GpuKeyCacheKey& other) const noexcept {
        return task_identity == other.task_identity &&
               parameter_identity == other.parameter_identity &&
               evaluation_context_identity == other.evaluation_context_identity &&
               evaluation_context_generation == other.evaluation_context_generation &&
               gpu_device == other.gpu_device && type == other.type &&
               source_node == other.source_node && level == other.level &&
               sp_level == other.sp_level && galois_element == other.galois_element;
    }
};

struct GpuKeyCacheKeyHash {
    size_t operator()(const GpuKeyCacheKey& key) const noexcept {
        size_t seed = 0;
        const auto combine = [&seed](auto value) {
            const size_t hashed = std::hash<decltype(value)>{}(value);
            seed ^= hashed + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U);
        };
        combine(key.task_identity);
        combine(key.parameter_identity);
        combine(key.evaluation_context_identity);
        combine(key.evaluation_context_generation);
        combine(key.gpu_device);
        combine(static_cast<int>(key.type));
        combine(key.source_node);
        combine(key.level);
        combine(key.sp_level);
        combine(key.galois_element);
        return seed;
    }
};

/**
 * Backend-owned cache of GPU-resident evaluation keys.
 *
 * The cache owns a dedicated upload stream and never retains the host ABI
 * structs used to populate a miss. Its namespace is fixed at construction and
 * includes task, parameter, evaluation-context generation, and CUDA device.
 */
template <heongpu::Scheme SchemeType> class GpuEvaluationKeyCache {
public:
    GpuEvaluationKeyCache(heongpu::HEContext<SchemeType> context,
                          std::vector<uint32_t> all_galois_elts,
                          uint64_t task_identity,
                          uint64_t parameter_identity,
                          uint64_t evaluation_context_identity,
                          uint64_t evaluation_context_generation,
                          int gpu_device)
        : context_(std::move(context)),
          all_galois_elts_(std::move(all_galois_elts)),
          task_identity_(task_identity),
          parameter_identity_(parameter_identity),
          evaluation_context_identity_(evaluation_context_identity),
          evaluation_context_generation_(evaluation_context_generation),
          gpu_device_(gpu_device) {
        CHECK(cudaSetDevice(gpu_device_));
        CHECK(cudaStreamCreate(&upload_stream_));
        upload_options_ = heongpu::ExecutionOptions().set_stream(upload_stream_);
    }

    GpuEvaluationKeyCache(const GpuEvaluationKeyCache&) = delete;
    GpuEvaluationKeyCache& operator=(const GpuEvaluationKeyCache&) = delete;

    ~GpuEvaluationKeyCache() {
        cudaSetDevice(gpu_device_);
        cudaStreamSynchronize(upload_stream_);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            relin_keys_.clear();
            galois_key_.reset();
            loaded_galois_keys_.clear();
            switch_keys_.clear();
        }
        cudaStreamSynchronize(upload_stream_);
        cudaStreamDestroy(upload_stream_);
    }

    std::shared_ptr<heongpu::Relinkey<SchemeType>>
    get_relin_key(const CRelinKey& source, const DatumNode& source_node) {
        const auto key = make_key(source_node, 0);
        std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = relin_keys_.find(key);
        if (existing != relin_keys_.end()) {
            ++stats_.hits;
            ++stats_.relin_hits;
            return existing->second;
        }

        auto result = std::make_shared<heongpu::Relinkey<SchemeType>>(context_, upload_options_);
        export_relin_key(source, *result, context_->get_ciphertext_modulus_count(),
                         context_->get_key_modulus_count());
        CHECK(cudaStreamSynchronize(upload_stream_));
        relin_keys_.emplace(key, result);
        ++stats_.misses;
        ++stats_.relin_misses;
        return result;
    }

    std::shared_ptr<heongpu::Galoiskey<SchemeType>>
    get_galois_key(const CGaloisKey& source,
                   const DatumNode& source_node,
                   uint32_t galois_element) {
        const auto key = make_key(source_node, galois_element);
        std::lock_guard<std::mutex> lock(mutex_);
        if (loaded_galois_keys_.find(key) != loaded_galois_keys_.end()) {
            ++stats_.hits;
            ++stats_.galois_hits;
            return galois_key_;
        }

        if (!galois_key_) {
            galois_key_ = std::make_shared<heongpu::Galoiskey<SchemeType>>(
                context_, all_galois_elts_, upload_options_);
        }
        export_galois_key(source, *galois_key_, galois_element,
                          context_->get_ciphertext_modulus_count(),
                          context_->get_key_modulus_count());
        CHECK(cudaStreamSynchronize(upload_stream_));
        loaded_galois_keys_.insert(key);
        ++stats_.misses;
        ++stats_.galois_misses;
        return galois_key_;
    }

    std::shared_ptr<heongpu::Switchkey<SchemeType>>
    get_switch_key(const CKeySwitchKey& source, const DatumNode& source_node) {
        const auto key = make_key(source_node, 0);
        std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = switch_keys_.find(key);
        if (existing != switch_keys_.end()) {
            ++stats_.hits;
            ++stats_.switch_hits;
            return existing->second;
        }

        auto result = std::make_shared<heongpu::Switchkey<SchemeType>>(context_, upload_options_);
        export_switching_key(source, *result, context_->get_ciphertext_modulus_count(),
                             context_->get_key_modulus_count());
        CHECK(cudaStreamSynchronize(upload_stream_));
        switch_keys_.emplace(key, result);
        ++stats_.misses;
        ++stats_.switch_misses;
        return result;
    }

    GpuKeyCacheSnapshot snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

private:
    GpuKeyCacheKey make_key(const DatumNode& source_node, uint32_t galois_element) const {
        return GpuKeyCacheKey{
            task_identity_,
            parameter_identity_,
            evaluation_context_identity_,
            evaluation_context_generation_,
            gpu_device_,
            source_node.datum_type,
            source_node.index,
            source_node.fhe_prop.has_value() ? source_node.fhe_prop->level : -1,
            source_node.fhe_prop.has_value() ? source_node.fhe_prop->sp_level : -1,
            galois_element,
        };
    }

    heongpu::HEContext<SchemeType> context_;
    std::vector<uint32_t> all_galois_elts_;
    uint64_t task_identity_;
    uint64_t parameter_identity_;
    uint64_t evaluation_context_identity_;
    uint64_t evaluation_context_generation_;
    int gpu_device_;
    cudaStream_t upload_stream_ = nullptr;
    heongpu::ExecutionOptions upload_options_;

    mutable std::mutex mutex_;
    std::unordered_map<GpuKeyCacheKey,
                       std::shared_ptr<heongpu::Relinkey<SchemeType>>,
                       GpuKeyCacheKeyHash>
        relin_keys_;
    std::shared_ptr<heongpu::Galoiskey<SchemeType>> galois_key_;
    std::unordered_set<GpuKeyCacheKey, GpuKeyCacheKeyHash> loaded_galois_keys_;
    std::unordered_map<GpuKeyCacheKey,
                       std::shared_ptr<heongpu::Switchkey<SchemeType>>,
                       GpuKeyCacheKeyHash>
        switch_keys_;
    GpuKeyCacheSnapshot stats_;
};

/**
 * @brief Import ciphertext from GPU device memory to C struct
 */
template <heongpu::Scheme SchemeType> void import_ciphertext(heongpu::Ciphertext<SchemeType>& src, CCiphertext* dest) {
    int N = src.ring_size();
    int n_component = src.level() + 1;

    // alloc_ciphertext() does not initialize scale. Leaving malloc garbage
    // here can make CKKS import override the parameter default scale and
    // decode an otherwise valid ciphertext as non-finite values.
    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        dest->scale = src.scale();
    } else {
        dest->scale = 0.0;
    }

    for (int i = 0; i < src.size(); i++) {
        for (int j = 0; j < n_component; j++) {
            CHECK(cudaMemcpyAsync(dest->polys[i].components[j].data, &src.data()[i * n_component * N + j * N],
                                  N * sizeof(uint64_t), cudaMemcpyDeviceToHost, src.stream()));
        }
    }
}

/**
 * @brief Create executor for loading ABI data to GPU (H2D transfer)
 *
 * Converts C struct to GPU types:
 * - CCiphertext → heongpu::Ciphertext
 * - CPlaintext → heongpu::Plaintext
 * - CRelinKey → heongpu::Relinkey
 * - CGaloisKey → heongpu::Galoiskey
 * - CKeySwitchKey → heongpu::Switchkey
 *
 * @tparam SchemeType GPU scheme type (heongpu::Scheme::BFV or heongpu::Scheme::CKKS)
 * @return ExecutorFunc that performs H2D transfer
 *
 * @note Input: std::shared_ptr<C struct> from available_data
 * @note Output: std::shared_ptr<GPU type> stored in std::any
 * @note Requires heongpu::HEContext in ExecutionContext other_args[0]
 * @note Requires heongpu::ExecutionOptions in ExecutionContext other_args[1]
 * @note Requires galois_key shared_ptr in ExecutionContext other_args[2]
 * @note Requires galois_key_mutex in ExecutionContext other_args[3]
 */
template <heongpu::Scheme SchemeType> ExecutorFunc create_load_to_gpu_executor() {
    return [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
              const ComputeNode& self) -> void {
        // Get GPU context and options from execution context
        auto* operators = ctx.get_arithmetic_context<heongpu::HEArithmeticOperator<SchemeType>>();
        auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);
        auto* context = ctx.get_other_arg<heongpu::HEContext<SchemeType>>(1);
        auto* galois_key_ptr = ctx.get_other_arg<std::shared_ptr<heongpu::Galoiskey<SchemeType>>>(2);
        auto* galois_key_mutex = ctx.get_other_arg<std::mutex>(3);
        auto* all_galois_elts = ctx.get_other_arg<std::vector<uint32_t>>(4);
        auto* key_cache = ctx.get_other_arg<GpuEvaluationKeyCache<SchemeType>>(5);
        auto* pinned_h2d_staging = ctx.get_other_arg<GpuPinnedH2DStaging>(6);

        if (!stream_option || !context) {
            throw std::runtime_error("GPU stream options or context not found in execution context");
        }

        // Get input node and data
        const DatumNode* input_node = self.input_nodes[0];
        // Determine data type and galois element
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        DataType data_type = input_node->datum_type;

        std::any c_struct = inputs.at(input_node->index);

        uint32_t galois_element = 0;
        if (data_type == TYPE_GALOIS_KEY && input_node->fhe_prop->p.has_value()) {
            galois_element = input_node->fhe_prop->p->galois_element;
        }

        // Perform H2D transfer based on data type
        std::any gpu_data = std::any{};

        switch (data_type) {
            case TYPE_PLAINTEXT: {
                auto c_pt_ptr = std::any_cast<std::shared_ptr<CPlaintext>>(c_struct);
                const CPlaintext* c_pt = c_pt_ptr.get();
                const bool is_ringt = input_node->fhe_prop->p.has_value() &&
                                      input_node->fhe_prop->p->is_ringt;
                std::shared_ptr<heongpu::Plaintext<SchemeType>> output_ptr;
                if constexpr (SchemeType == heongpu::Scheme::CKKS) {
                    output_ptr = std::make_shared<heongpu::Plaintext<SchemeType>>(
                        *context, c_pt->level, is_ringt, *stream_option);
                } else {
                    output_ptr = std::make_shared<heongpu::Plaintext<SchemeType>>(
                        *context, c_pt->level, *stream_option);
                    output_ptr->set_ringt(is_ringt);
                }
                export_plaintext(*c_pt, *output_ptr, pinned_h2d_staging);
                gpu_data = output_ptr;
                break;
            }
            case TYPE_CIPHERTEXT: {
                auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(c_struct);
                const CCiphertext* c_ct = c_ct_ptr.get();
                auto output_ptr =
                    std::make_shared<heongpu::Ciphertext<SchemeType>>(*context, c_ct->level, *stream_option);
                export_ciphertext(*c_ct, *output_ptr, pinned_h2d_staging);
                gpu_data = output_ptr;
                break;
            }
            case TYPE_RELIN_KEY: {
                auto c_rlk_ptr = std::any_cast<std::shared_ptr<CRelinKey>>(c_struct);
                const CRelinKey* c_rlk = c_rlk_ptr.get();
                if (key_cache) {
                    gpu_data = key_cache->get_relin_key(*c_rlk, *input_node);
                    break;
                }
                auto rlk_ptr = std::make_shared<heongpu::Relinkey<SchemeType>>(*context, *stream_option);
                export_relin_key(*c_rlk, *rlk_ptr, (*context)->get_ciphertext_modulus_count(),
                                 (*context)->get_key_modulus_count());
                gpu_data = rlk_ptr;
                break;
            }
            case TYPE_GALOIS_KEY: {
                auto c_glk_ptr = std::any_cast<std::shared_ptr<CGaloisKey>>(c_struct);
                const CGaloisKey* c_glk = c_glk_ptr.get();

                if (key_cache) {
                    gpu_data = key_cache->get_galois_key(*c_glk, *input_node, galois_element);
                    break;
                }

                // All GLK data nodes write into one shared HEonGPU Galoiskey.
                // Keep initialization, export, and synchronization together so
                // readiness cannot race an H2D copy on the key object's stream.
                {
                    std::lock_guard<std::mutex> lock(*galois_key_mutex);
                    if (!(*galois_key_ptr)) {
                        // Initialize with all galois elements from mega_ag
                        *galois_key_ptr = std::make_shared<heongpu::Galoiskey<SchemeType>>(*context, *all_galois_elts,
                                                                                           *stream_option);
                    }

                    export_galois_key(*c_glk, **galois_key_ptr, galois_element,
                                      (*context)->get_ciphertext_modulus_count(),
                                      (*context)->get_key_modulus_count());
                    CHECK(cudaStreamSynchronize((*galois_key_ptr)->stream()));
                }
                gpu_data = *galois_key_ptr;
                break;
            }
            case TYPE_SWITCH_KEY: {
                auto c_swk_ptr = std::any_cast<std::shared_ptr<CKeySwitchKey>>(c_struct);
                const CKeySwitchKey* c_swk = c_swk_ptr.get();
                if (key_cache) {
                    gpu_data = key_cache->get_switch_key(*c_swk, *input_node);
                    break;
                }
                auto swk_ptr = std::make_shared<heongpu::Switchkey<SchemeType>>(*context, *stream_option);
                export_switching_key(*c_swk, *swk_ptr, (*context)->get_ciphertext_modulus_count(),
                                     (*context)->get_key_modulus_count());
                gpu_data = swk_ptr;
                break;
            }
            default: throw std::runtime_error("Unsupported data type in H2D transfer");
        }

        // C structs own temporary host buffers. Complete H2D copies before
        // the ABI layer is allowed to release them.
        CHECK(cudaStreamSynchronize(stream_option->stream_));

        // Output is the GPU data
        output = gpu_data;
    };
}

/**
 * @brief Create executor for storing GPU data to ABI (D2H transfer)
 *
 * Converts GPU types to C struct:
 * - heongpu::Ciphertext → CCiphertext
 * - heongpu::Plaintext → CPlaintext
 *
 * @tparam SchemeType GPU scheme type (heongpu::Scheme::BFV or heongpu::Scheme::CKKS)
 * @return ExecutorFunc that performs D2H transfer
 *
 * @note Input: std::shared_ptr<GPU type> from available_data
 * @note Output: std::shared_ptr<C struct> stored in std::any
 * @note C struct memory is allocated here and freed by shared_ptr deleter
 */
template <heongpu::Scheme SchemeType> ExecutorFunc create_store_from_gpu_executor() {
    return [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
              const ComputeNode& self) -> void {
        // Get input node and GPU data
        const DatumNode* input_node = self.input_nodes[0];
        // Determine data type
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        DataType data_type = input_node->datum_type;

        std::any gpu_data = inputs.at(input_node->index);

        // Perform D2H transfer and allocate C struct
        std::any c_struct;

        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto gpu_ct = std::any_cast<std::shared_ptr<heongpu::Ciphertext<SchemeType>>>(gpu_data);

                auto* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                alloc_ciphertext(c_ct, gpu_ct->size() - 1, gpu_ct->level(), gpu_ct->ring_size());
                c_struct = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* ptr) {
                    free_ciphertext(ptr);
                    free(ptr);
                });

                import_ciphertext(*gpu_ct, c_ct);
                break;
            }
            default: throw std::runtime_error("Unsupported data type for D2H transfer");
        }

        // Output is the allocated C struct
        output = c_struct;
    };
}

#endif  // GPU_ABI_BRIDGE_EXECUTORS_H
