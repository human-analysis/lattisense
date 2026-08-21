// Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <unordered_map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <set>
#include <memory>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <HEonGPU-1.1/heongpu/heongpu.hpp>

#include "nlohmann/json.hpp"
#include "../lib/thread_pool/BS_thread_pool.hpp"
#include "../lib/gsl/span"

#include "../wrapper.h"
#include "../mega_ag.h"
#include "gpu_abi_bridge_executors.h"
#include "../cpu_task_utils.h"
#include "../../fhe_ops_lib/fhe_lib_v2.h"

#ifdef LATTISENSE_DEV
#    include "gpu_mem_monitor.h"
#endif

extern "C" {
#include "../../abi/c_types.h"
#include "../../abi/c_structs.h"
}

namespace gpu_wrapper {
using namespace fhe_ops_lib;

template <heongpu::Scheme SchemeType>
void init_gpu_context(const nlohmann::json& param_json,
                      heongpu::HEContext<SchemeType>& context,
                      std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>>& operators) {
    auto n = param_json["n"].get<int>();

    auto max_level = param_json["max_level"].get<int>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();

    heongpu::MemoryPoolConfig pool_config = heongpu::MemoryPoolConfig::Defaults();

    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        context = heongpu::GenHEContext<SchemeType>(heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(n);

        int slots = param_json["slots"].get<int>();
        context->set_slot_count(slots);

        std::vector<Data64> Q, P;
        for (int i = 0; i <= max_level; i++) {
            Q.push_back(Data64(q[i]));
        }

        for (int i = 0; i < p.size(); i++) {
            P.push_back(Data64(p[i]));
        }
        context->set_coeff_modulus_values(Q, P);
        context->generate(pool_config);

        auto gpu_encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(context, *gpu_encoder);

        if (param_json.contains("btp_output_level")) {
            int cts_start_level = param_json["btp_cts_start_level"].get<int>();
            int cts_depth = param_json["btp_cts_depth"].get<int>();
            double cts_bsgs_ratio = param_json["btp_cts_bsgs_ratio"].get<double>();

            uint64_t eval_mod_q = param_json["btp_eval_mod_q"].get<uint64_t>();
            int eval_mod_start_level = param_json["btp_eval_mod_start_level"].get<int>();
            double eval_mod_scaling_factor = param_json["btp_eval_mod_scaling_factor"].get<double>();
            double eval_mod_message_ratio = param_json["btp_eval_mod_message_ratio"].get<double>();
            int eval_mod_k = param_json["btp_eval_mod_k"].get<int>();
            int eval_mod_sine_deg = param_json["btp_eval_mod_sine_deg"].get<int>();
            int eval_mod_double_angle = param_json["btp_eval_mod_double_angle"].get<int>();
            int eval_mod_arcsine_deg = param_json["btp_eval_mod_arcsine_deg"].get<int>();

            int stc_start_level = param_json["btp_stc_start_level"].get<int>();
            int stc_depth = param_json["btp_stc_depth"].get<int>();
            double stc_bsgs_ratio = param_json["btp_stc_bsgs_ratio"].get<double>();

            double scale = param_json["scale"].get<double>();

            heongpu::EncodingMatrixConfig cts_config(heongpu::LinearTransformType::COEFFS_TO_SLOTS, cts_start_level,
                                                     cts_bsgs_ratio, cts_depth);
            heongpu::EvalModConfig eval_mod_config(eval_mod_q, eval_mod_start_level, eval_mod_message_ratio, eval_mod_k,
                                                   eval_mod_sine_deg, eval_mod_double_angle, eval_mod_arcsine_deg,
                                                   eval_mod_scaling_factor);
            heongpu::EncodingMatrixConfig stc_config(heongpu::LinearTransformType::SLOTS_TO_COEFFS, stc_start_level,
                                                     stc_bsgs_ratio, stc_depth);

            heongpu::BootstrappingConfigV2 boot_config(stc_config, eval_mod_config, cts_config);

            operators->generate_bootstrapping_params_v2(scale, boot_config);
        }

    } else {
        int t = param_json["t"].get<uint64_t>();
        context = heongpu::GenHEContext<SchemeType>(heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(n);

        std::vector<Data64> Q, P;
        for (int i = 0; i <= max_level; i++) {
            Q.push_back(Data64(q[i]));
        }
        for (int i = 0; i < p.size(); i++) {
            P.push_back(Data64(p[i]));
        }
        context->set_coeff_modulus_values(Q, P);
        context->set_plain_modulus(t);
        context->generate(pool_config);

        auto gpu_encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(context, *gpu_encoder);
    }
}

bool gpu_key_cache_enabled() {
    const char* value = std::getenv("LATTISENSE_GPU_KEY_CACHE");
    return value != nullptr && value[0] != '\0' && std::strcmp(value, "0") != 0;
}

bool gpu_key_cache_stats_enabled() {
    return std::getenv("LATTISENSE_GPU_KEY_CACHE_STATS") != nullptr;
}

bool gpu_pinned_request_h2d_enabled() {
    const char* value = std::getenv("LATTISENSE_GPU_PIN_REQUEST_H2D");
    return value != nullptr && value[0] != '\0' && std::strcmp(value, "0") != 0;
}

bool gpu_pinned_request_h2d_stats_enabled() {
    const char* value = std::getenv("LATTISENSE_GPU_PIN_REQUEST_H2D_STATS");
    return value != nullptr && value[0] != '\0' && std::strcmp(value, "0") != 0;
}

bool gpu_event_cache_enabled() {
    const char* value = std::getenv("LATTISENSE_GPU_EVENT_CACHE");
    return value != nullptr && value[0] != '\0' && std::strcmp(value, "0") != 0;
}

bool gpu_event_cache_stats_enabled() {
    return std::getenv("LATTISENSE_GPU_EVENT_CACHE_STATS") != nullptr;
}

bool gpu_operator_submission_lock_enabled() {
    const char* value = std::getenv("LATTISENSE_GPU_OPERATOR_SUBMISSION_LOCK");
    return value != nullptr && value[0] != '\0' && std::strcmp(value, "0") != 0;
}

bool gpu_bootstrap_submission_lock_enabled() {
    const char* value = std::getenv("LATTISENSE_GPU_BOOTSTRAP_SUBMISSION_LOCK");
    return value != nullptr && value[0] != '\0' && std::strcmp(value, "0") != 0;
}

std::vector<uint32_t> collect_galois_elements(const MegaAG& mega_ag) {
    std::vector<uint32_t> result;
    for (const auto& [data_index, data_node] : mega_ag.data) {
        if (data_node.datum_type == DataType::TYPE_GALOIS_KEY && data_node.fhe_prop->p.has_value()) {
            result.push_back(data_node.fhe_prop->p->galois_element);
        }
    }
    return result;
}

template <heongpu::Scheme SchemeType> struct PersistentGpuRuntime {
    PersistentGpuRuntime(const nlohmann::json& parameter,
                         std::vector<uint32_t> all_galois_elts,
                         uint64_t task_identity_arg,
                         uint64_t evaluation_context_identity_arg,
                         uint64_t evaluation_context_generation_arg,
                         int gpu_device_arg)
        : task_identity(task_identity_arg),
          parameter_identity(std::hash<std::string>{}(parameter.dump())),
          evaluation_context_identity(evaluation_context_identity_arg),
          evaluation_context_generation(evaluation_context_generation_arg),
          gpu_device(gpu_device_arg) {
        CHECK(cudaSetDevice(gpu_device));
        init_gpu_context<SchemeType>(parameter, context, operators);
        key_cache = std::make_unique<GpuEvaluationKeyCache<SchemeType>>(
            context, std::move(all_galois_elts), task_identity, parameter_identity,
            evaluation_context_identity, evaluation_context_generation, gpu_device);
    }

    ~PersistentGpuRuntime() {
        cudaSetDevice(gpu_device);
        cudaDeviceSynchronize();
        for (const auto& [node_index, event] : data_ready_event_cache) {
            (void)node_index;
            cudaEventDestroy(event);
        }
    }

    cudaEvent_t get_data_ready_event(NodeIndex node_index) {
        std::lock_guard<std::mutex> lock(data_ready_event_cache_mutex);
        const auto cached = data_ready_event_cache.find(node_index);
        if (cached != data_ready_event_cache.end()) {
            return cached->second;
        }
        cudaEvent_t event;
        CHECK(cudaEventCreate(&event));
        data_ready_event_cache.emplace(node_index, event);
        return event;
    }

    size_t data_ready_event_cache_size() const {
        std::lock_guard<std::mutex> lock(data_ready_event_cache_mutex);
        return data_ready_event_cache.size();
    }

    bool matches(uint64_t task_identity_arg,
                 uint64_t parameter_identity_arg,
                 uint64_t evaluation_context_identity_arg,
                 uint64_t evaluation_context_generation_arg,
                 int gpu_device_arg) const {
        return task_identity == task_identity_arg &&
               parameter_identity == parameter_identity_arg &&
               evaluation_context_identity == evaluation_context_identity_arg &&
               evaluation_context_generation == evaluation_context_generation_arg &&
               gpu_device == gpu_device_arg;
    }

    uint64_t task_identity;
    uint64_t parameter_identity;
    uint64_t evaluation_context_identity;
    uint64_t evaluation_context_generation;
    int gpu_device;
    heongpu::HEContext<SchemeType> context;
    std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>> operators;
    std::unique_ptr<GpuEvaluationKeyCache<SchemeType>> key_cache;
    mutable std::mutex data_ready_event_cache_mutex;
    std::unordered_map<NodeIndex, cudaEvent_t> data_ready_event_cache;
};

template <heongpu::Scheme SchemeType, typename TContext>
void _run_mega_ag_impl(gsl::span<CArgument> input_args,
                       gsl::span<CArgument> output_args,
                       const MegaAG& mega_ag,
                       ProgressCallback progress_cb = nullptr,
                       int gpu_device = 0,
                       PersistentGpuRuntime<SchemeType>* persistent_runtime = nullptr,
                       uint64_t evaluation_context_identity = 0,
                       uint64_t evaluation_context_generation = 0) {
    // cudaSetDevice is thread-local; new threads in the pool default to device 0.
    // Use the runtime-specified device so all worker threads bind to the same device.
    const int device = gpu_device;
    CHECK(cudaSetDevice(device));

    // Initialize GPU context and operators for GPU FHE operations
    heongpu::HEContext<SchemeType> local_context;
    std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>> local_operators;
    heongpu::HEContext<SchemeType>* context_ptr = nullptr;
    heongpu::HEArithmeticOperator<SchemeType>* operators = nullptr;
    GpuEvaluationKeyCache<SchemeType>* key_cache = nullptr;
    if (persistent_runtime != nullptr) {
        context_ptr = &persistent_runtime->context;
        operators = persistent_runtime->operators.get();
        key_cache = persistent_runtime->key_cache.get();
    } else {
        init_gpu_context<SchemeType>(mega_ag.parameter, local_context, local_operators);
        context_ptr = &local_context;
        operators = local_operators.get();
    }
    auto& context = *context_ptr;
    const bool reuse_data_ready_events = persistent_runtime != nullptr && gpu_event_cache_enabled();
    const GpuKeyCacheSnapshot cache_stats_before =
        key_cache != nullptr ? key_cache->snapshot() : GpuKeyCacheSnapshot{};

    // GPU streams for FHE computations
    const int num_streams = 4;
    std::vector<cudaStream_t> streams(num_streams);
    std::vector<heongpu::ExecutionOptions> stream_options(num_streams);
    GpuPinnedH2DStats pinned_h2d_stats;
    std::vector<std::unique_ptr<GpuPinnedH2DStaging>> pinned_h2d_staging(num_streams);
    if (gpu_pinned_request_h2d_enabled()) {
        for (auto& staging : pinned_h2d_staging) {
            staging = std::make_unique<GpuPinnedH2DStaging>(pinned_h2d_stats);
        }
    }

    // GPU thread pool for GPU FHE operations (priority-enabled to avoid high-priority tasks being starved)
    BS::priority_thread_pool gpu_pool(num_streams);

    for (int i = 0; i < num_streams; i++) {
        CHECK(cudaStreamCreate(&streams[i]));
        stream_options[i] = heongpu::ExecutionOptions().set_stream(streams[i]);
    }

    // CPU thread pool for CPU tasks (custom nodes + ABI bridge nodes)
    const int num_cpu_threads = std::min(16, static_cast<int>(std::thread::hardware_concurrency())) - num_streams;
    BS::priority_thread_pool cpu_pool(num_cpu_threads > 0 ? num_cpu_threads : 1);

    // Create CPU contexts for CPU nodes (ABI bridge only, no keys needed)
    constexpr HEScheme cpu_scheme = (SchemeType == heongpu::Scheme::BFV) ? HEScheme::BFV : HEScheme::CKKS;
    std::unique_ptr<TContext> base_cpu_context;
    init_empty_context<cpu_scheme, TContext>(mega_ag.parameter, base_cpu_context);

    std::vector<void*> input_handles = extract_input_handles(input_args);

    std::unordered_map<NodeIndex, std::any> available_data = init_available_data(mega_ag, input_handles);

    // Build output handle map: output NodeIndex -> void* handle pointer
    std::unordered_map<NodeIndex, void*> output_handle_map = extract_output_handle_map(mega_ag, output_args);

    // GPU-specific data structures
    std::unordered_map<NodeIndex, cudaEvent_t> data_ready_events;
    std::shared_ptr<heongpu::Galoiskey<SchemeType>> galois_key;
    std::mutex galois_key_mutex;
    std::mutex operator_submission_mutex;
    const bool lock_operator_submission = gpu_operator_submission_lock_enabled();
    const bool lock_bootstrap_submission = gpu_bootstrap_submission_lock_enabled();

    // Collect all galois elements from data nodes
    std::vector<uint32_t> all_galois_elts = collect_galois_elements(mega_ag);

    // Define GPU task submission function
    // This receives shared state from run_tasks
    std::function<void(NodeIndex, std::mutex&, std::priority_queue<TaskInfo>&, std::set<NodeIndex>&,
                       std::atomic<size_t>&, std::atomic<size_t>&, std::condition_variable&, std::mutex&,
                       std::unordered_map<NodeIndex, std::atomic<int>>&)>
        submit_gpu_task = [&](NodeIndex task_index, std::mutex& m_mutex, std::priority_queue<TaskInfo>& task_queue,
                              std::set<NodeIndex>& queued_computes, std::atomic<size_t>& completed_tasks,
                              std::atomic<size_t>& total_tasks, std::condition_variable& completion_cv,
                              std::mutex& completion_mutex,
                              std::unordered_map<NodeIndex, std::atomic<int>>& data_ref_counts) {
            const BS::priority_t pool_priority = mega_ag.computes.at(task_index).priority;
            gpu_pool.detach_task(
                [task_index, pool_priority, device, &gpu_pool, &mega_ag, &m_mutex, &task_queue, &queued_computes,
                 &completed_tasks, &total_tasks, &completion_cv, &completion_mutex, &available_data, operators,
                 &data_ready_events, &stream_options, &streams, &context, &galois_key, &galois_key_mutex,
                 &data_ref_counts, &all_galois_elts, key_cache, &pinned_h2d_staging, persistent_runtime,
                 reuse_data_ready_events, &operator_submission_mutex, lock_operator_submission,
                 lock_bootstrap_submission]() {
                    CHECK(cudaSetDevice(device));
                    auto stream_id = BS::this_thread::get_index().value();

                    const ComputeNode& compute_node = mega_ag.computes.at(task_index);

                    // Get operation type outside lock
                    OperationType op =
                        compute_node.fhe_prop.has_value() ? compute_node.fhe_prop->op_type : OperationType::UNKNOWN;

                    const std::vector<DatumNode*>& compute_input_nodes = compute_node.input_nodes;
                    const DatumNode* compute_output_node = compute_node.output_nodes[0];

                    std::vector<cudaEvent_t> events_to_wait;
                    std::unordered_map<uint64_t, std::any> thread_input_cache;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        // Check if all BACKEND input events are available
                        // ABI inputs (from CPU via LOAD_TO_BACKEND) don't have events
                        bool events_ready = true;
                        if (op != OperationType::LOAD_TO_BACKEND) {
                            for (const auto* input_node : compute_input_nodes) {
                                auto event_it = data_ready_events.find(input_node->index);
                                if (event_it == data_ready_events.end()) {
                                    events_ready = false;
                                    break;
                                }
                            }
                        }

                        if (!events_ready) {
                            queued_computes.erase(task_index);
                            task_queue.push({mega_ag.computes.at(task_index).priority, task_index});
                            return;
                        }

                        // Collect events to wait for and cache data pointers
                        for (const auto* input_node : compute_input_nodes) {
                            // Cache input data
                            thread_input_cache[input_node->index] = available_data[input_node->index];

                            // Collect events for GPU backend inputs
                            // LOAD_TO_BACKEND loads from CPU (no events), other ops use GPU inputs (have events)
                            if (op != OperationType::LOAD_TO_BACKEND) {
                                events_to_wait.push_back(data_ready_events[input_node->index]);
                            }
                        }
                    }

                    // Wait for all required events outside of locks
                    for (auto& event : events_to_wait) {
                        CHECK(cudaStreamWaitEvent(streams[stream_id], event, 0));
                    }

                    // Execute computation using unified executor
                    ExecutionContext exec_ctx;
                    exec_ctx.context = operators;
                    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
                        exec_ctx.bootstrap_input_scale = mega_ag.parameter["scale"].get<double>();
                        exec_ctx.bootstrap_target_scale = std::exp2(std::round(std::log2(
                            mega_ag.parameter["btp_eval_mod_q"].get<double>() /
                            mega_ag.parameter["btp_eval_mod_message_ratio"].get<double>())));
                        exec_ctx.bootstrap_rescale_scale = mega_ag.parameter["q"][1].get<double>();
                    }
                    exec_ctx.other_args.push_back(&stream_options[stream_id]);

                    // LOAD_TO_BACKEND needs HEContext and galois_key parameters
                    if (op == OperationType::LOAD_TO_BACKEND) {
                        exec_ctx.other_args.push_back(&context);
                        exec_ctx.other_args.push_back(&galois_key);
                        exec_ctx.other_args.push_back(&galois_key_mutex);
                        exec_ctx.other_args.push_back(&all_galois_elts);
                        exec_ctx.other_args.push_back(key_cache);
                        exec_ctx.other_args.push_back(pinned_h2d_staging[stream_id].get());
                    }

                    std::any output;

                    // Allocate output based on operation type
                    // GPU FHE ops: pre-allocate GPU ciphertext (except LOAD and STORE which handle allocation
                    // internally) LOAD_TO_BACKEND: allocates GPU memory internally STORE_FROM_BACKEND: outputs to C
                    // struct (not GPU memory)
                    if (op != OperationType::LOAD_TO_BACKEND && op != OperationType::STORE_FROM_BACKEND) {
                        int output_level = compute_output_node->fhe_prop->level;
                        auto output_ptr = std::make_shared<heongpu::Ciphertext<SchemeType>>(context, output_level,
                                                                                            stream_options[stream_id]);
                        output = output_ptr;
                    }

                    try {
                        std::unique_lock<std::mutex> submission_lock(operator_submission_mutex, std::defer_lock);
                        if (lock_operator_submission ||
                            (lock_bootstrap_submission && op == OperationType::BOOTSTRAP)) {
                            submission_lock.lock();
                        }
                        compute_node.executor(exec_ctx, thread_input_cache, output, compute_node);
                    } catch (const std::exception& error) {
                        std::fprintf(stderr, "[GPU task exception] node=%llu op=%d: %s\n",
                                     static_cast<unsigned long long>(task_index), static_cast<int>(op),
                                     error.what());
                        if constexpr (SchemeType == heongpu::Scheme::CKKS) {
                            for (const auto* input_node : compute_input_nodes) {
                                const int graph_level = input_node->fhe_prop.has_value()
                                                            ? input_node->fhe_prop->level
                                                            : -1;
                                const auto input_it = thread_input_cache.find(input_node->index);
                                if (input_it != thread_input_cache.end()) {
                                    if (const auto* ciphertext =
                                            std::any_cast<std::shared_ptr<heongpu::Ciphertext<SchemeType>>>(
                                                &input_it->second);
                                        ciphertext && *ciphertext) {
                                        std::fprintf(stderr,
                                                     "  input=%llu graph_level=%d actual_level=%d depth=%d "
                                                     "scale=%.17g\n",
                                                     static_cast<unsigned long long>(input_node->index), graph_level,
                                                     (*ciphertext)->level(), (*ciphertext)->depth(),
                                                     (*ciphertext)->scale());
                                    }
                                }
                            }
                        }
                        std::fflush(stderr);
                        std::abort();
                    }

                    // Create event for GPU backend outputs (not STORE_FROM_BACKEND which outputs to C struct)
                    cudaEvent_t output_event;
                    bool has_output_event = false;
                    if (op != OperationType::STORE_FROM_BACKEND) {
                        if (reuse_data_ready_events) {
                            output_event = persistent_runtime->get_data_ready_event(compute_output_node->index);
                        } else {
                            CHECK(cudaEventCreate(&output_event));
                        }
                        CHECK(cudaEventRecord(output_event, streams[stream_id]));
                        has_output_event = true;
                    }

                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        // Store output in available_data
                        available_data[compute_output_node->index] = output;

                        // Store event if created
                        if (has_output_event) {
                            data_ready_events[compute_output_node->index] = output_event;
                        }

                        // Update available computes
                        std::unordered_set<NodeIndex> newly_available_computes =
                            mega_ag.step_available_computes(*compute_output_node, available_data);

                        for (const auto& new_task_index : newly_available_computes) {
                            if (queued_computes.find(new_task_index) == queued_computes.end()) {
                                task_queue.push({mega_ag.computes.at(new_task_index).priority, new_task_index});
                                queued_computes.insert(new_task_index);
                            }
                        }
                    }

                    gpu_pool.detach_task(
                        [compute_node, output_event, has_output_event, device, &mega_ag, &m_mutex, &available_data,
                         &data_ref_counts]() {
                            CHECK(cudaSetDevice(device));
                            // Wait for GPU computation to complete if event exists
                            if (has_output_event) {
                                CHECK(cudaEventSynchronize(output_event));
                            }

                            {
                                std::lock_guard<std::mutex> lock(m_mutex);
                                mega_ag.purge_unused_data(compute_node, data_ref_counts, available_data);
                            }
                        },
                        pool_priority);

                    // Check if all tasks are completed (in this thread, not async lambda)
                    if (completed_tasks.fetch_add(1) + 1 >= total_tasks) {
                        std::lock_guard<std::mutex> lock(completion_mutex);
                        completion_cv.notify_all();
                    }
                },
                pool_priority);
        };

    // Define get_other_args for IMPORT_FROM_ABI nodes: pass output Handle* as other_arg
    auto get_other_args = [&](const ComputeNode& compute_node) -> std::vector<std::any> {
        std::vector<std::any> other_args_vec;
        if (compute_node.fhe_prop.has_value() && compute_node.fhe_prop->op_type == OperationType::IMPORT_FROM_ABI) {
            NodeIndex output_node_index = compute_node.output_nodes[0]->index;
            auto it = output_handle_map.find(output_node_index);
            if (it != output_handle_map.end()) {
                other_args_vec.push_back(it->second);
            }
        }
        return other_args_vec;
    };

    // Run tasks using common run_tasks function
    // CPU pool handles CPU nodes, GPU tasks submitted via submit_gpu_task
    // Pass cleanup to wait for GPU pool and clean up events before returning
#ifdef LATTISENSE_DEV
    GpuMemoryMonitor gpu_mem_monitor(100);  // sample every 100 ms
    gpu_mem_monitor.start(GpuMemoryMonitor::next_csv_path("mem_usage_gpu"));
#endif
    run_tasks(
        mega_ag, cpu_pool, base_cpu_context, available_data, get_other_args, submit_gpu_task,
        [&gpu_pool, &data_ready_events, reuse_data_ready_events]() {
            gpu_pool.wait();
            if (!reuse_data_ready_events) {
                for (auto& pair : data_ready_events) {
                    cudaEvent_t event = pair.second;
                    gpu_pool.detach_task([event]() { CHECK(cudaEventDestroy(event)); });
                }
            }
            gpu_pool.wait();
        },
        progress_cb);
    if (reuse_data_ready_events && gpu_event_cache_stats_enabled()) {
        std::fprintf(stderr, "[GPU Event Cache] enabled=1 device=%d cached_events=%zu\n", gpu_device,
                     persistent_runtime->data_ready_event_cache_size());
        std::fflush(stderr);
    }
    if (key_cache != nullptr && gpu_key_cache_stats_enabled()) {
        const GpuKeyCacheSnapshot after = key_cache->snapshot();
        std::fprintf(
            stderr,
            "[GPU Key Cache] enabled=1 device=%d context=%llu generation=%llu "
            "request_hits=%llu request_misses=%llu relin=%llu/%llu galois=%llu/%llu "
            "switch=%llu/%llu lifetime_hits=%llu lifetime_misses=%llu\n",
            gpu_device,
            static_cast<unsigned long long>(evaluation_context_identity),
            static_cast<unsigned long long>(evaluation_context_generation),
            static_cast<unsigned long long>(after.hits - cache_stats_before.hits),
            static_cast<unsigned long long>(after.misses - cache_stats_before.misses),
            static_cast<unsigned long long>(after.relin_hits - cache_stats_before.relin_hits),
            static_cast<unsigned long long>(after.relin_misses - cache_stats_before.relin_misses),
            static_cast<unsigned long long>(after.galois_hits - cache_stats_before.galois_hits),
            static_cast<unsigned long long>(after.galois_misses - cache_stats_before.galois_misses),
            static_cast<unsigned long long>(after.switch_hits - cache_stats_before.switch_hits),
            static_cast<unsigned long long>(after.switch_misses - cache_stats_before.switch_misses),
            static_cast<unsigned long long>(after.hits),
            static_cast<unsigned long long>(after.misses));
        std::fflush(stderr);
    }
    if (gpu_pinned_request_h2d_stats_enabled()) {
        std::fprintf(
            stderr,
            "[GPU Pinned Request H2D] enabled=%d device=%d staged_objects=%llu staged_bytes=%llu "
            "original_segments=%llu allocations=%llu allocation_bytes=%llu allocation_failures=%llu "
            "packing_ms=%.3f fallbacks=%llu\n",
            gpu_pinned_request_h2d_enabled() ? 1 : 0,
            gpu_device,
            static_cast<unsigned long long>(pinned_h2d_stats.staged_objects.load()),
            static_cast<unsigned long long>(pinned_h2d_stats.staged_bytes.load()),
            static_cast<unsigned long long>(pinned_h2d_stats.original_segments.load()),
            static_cast<unsigned long long>(pinned_h2d_stats.allocation_count.load()),
            static_cast<unsigned long long>(pinned_h2d_stats.allocation_bytes.load()),
            static_cast<unsigned long long>(pinned_h2d_stats.allocation_failures.load()),
            static_cast<double>(pinned_h2d_stats.packing_nanoseconds.load()) / 1.0e6,
            static_cast<unsigned long long>(pinned_h2d_stats.fallback_count.load()));
        std::fflush(stderr);
    }
#ifdef LATTISENSE_DEV
    gpu_mem_monitor.stop();
#endif
}

// Dispatch function to call _run_mega_ag_impl with appropriate TContext
template <heongpu::Scheme SchemeType>
void _run_mega_ag(gsl::span<CArgument> input_args,
                  gsl::span<CArgument> output_args,
                  const MegaAG& mega_ag,
                  ProgressCallback progress_cb = nullptr,
                  int gpu_device = 0,
                  PersistentGpuRuntime<SchemeType>* persistent_runtime = nullptr,
                  uint64_t evaluation_context_identity = 0,
                  uint64_t evaluation_context_generation = 0) {
    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        if (mega_ag.parameter.contains("btp_output_level")) {
            _run_mega_ag_impl<SchemeType, CkksBtpContext>(
                input_args, output_args, mega_ag, progress_cb, gpu_device, persistent_runtime,
                evaluation_context_identity, evaluation_context_generation);
        } else {
            _run_mega_ag_impl<SchemeType, CkksContext>(
                input_args, output_args, mega_ag, progress_cb, gpu_device, persistent_runtime,
                evaluation_context_identity, evaluation_context_generation);
        }
    } else {
        _run_mega_ag_impl<SchemeType, BfvContext>(
            input_args, output_args, mega_ag, progress_cb, gpu_device, persistent_runtime,
            evaluation_context_identity, evaluation_context_generation);
    }
}

class FheGpuTask {
public:
    FheGpuTask(const std::string& project_path) {
        mega_ag_ = MegaAG::load(project_path + "/mega_ag.json", Processor::GPU,
                                ScheduleMode::MAKESPAN_FIRST);
    }

    ~FheGpuTask() {}

    void bind_abi_bridge_executors(const ExecutorFunc& abi_export, const ExecutorFunc& abi_import) {
        // Create GPU backend bridge executors based on algorithm
        ExecutorFunc load_to_gpu;
        ExecutorFunc store_from_gpu;

        if (mega_ag_.algo == ALGO_BFV) {
            load_to_gpu = create_load_to_gpu_executor<heongpu::Scheme::BFV>();
            store_from_gpu = create_store_from_gpu_executor<heongpu::Scheme::BFV>();
        } else if (mega_ag_.algo == ALGO_CKKS) {
            load_to_gpu = create_load_to_gpu_executor<heongpu::Scheme::CKKS>();
            store_from_gpu = create_store_from_gpu_executor<heongpu::Scheme::CKKS>();
        } else {
            throw std::runtime_error("Unsupported algorithm for GPU bridge executors");
        }

        // Bind ABI bridge executors (export, import, load, store)
        mega_ag_.bind_abi_bridge_executors(abi_export, abi_import, load_to_gpu, store_from_gpu);
    }

    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) {
        mega_ag_.bind_custom_executors(custom_executors);
    }

    int run(gsl::span<CArgument> input_args,
            gsl::span<CArgument> output_args,
            ProgressCallback progress_cb = nullptr,
            int gpu_device = 0,
            uint64_t evaluation_context_identity = 0,
            uint64_t evaluation_context_handle = 0) {
        CHECK(cudaSetDevice(gpu_device));

        const bool cache_enabled = gpu_key_cache_enabled();
        std::unique_lock<std::mutex> cache_lock(key_cache_mutex_);
        if (last_evaluation_context_identity_ != evaluation_context_identity ||
            last_evaluation_context_handle_ != evaluation_context_handle) {
            last_evaluation_context_identity_ = evaluation_context_identity;
            last_evaluation_context_handle_ = evaluation_context_handle;
            ++evaluation_context_generation_;
        }
        const uint64_t evaluation_context_generation = evaluation_context_generation_;
        if (!cache_enabled) {
            ckks_runtime_.reset();
            bfv_runtime_.reset();
            cache_lock.unlock();
        }

        uint64_t task_identity = 0;
        uint64_t parameter_identity = 0;
        std::vector<uint32_t> all_galois_elts;
        if (cache_enabled) {
            task_identity = reinterpret_cast<uint64_t>(this);
            parameter_identity = std::hash<std::string>{}(mega_ag_.parameter.dump());
            all_galois_elts = collect_galois_elements(mega_ag_);
        }

        switch (mega_ag_.algo) {
            case Algo::ALGO_BFV: {
                PersistentGpuRuntime<heongpu::Scheme::BFV>* runtime = nullptr;
                if (cache_enabled) {
                    if (!bfv_runtime_ ||
                        !bfv_runtime_->matches(task_identity, parameter_identity, evaluation_context_identity,
                                               evaluation_context_generation, gpu_device)) {
                        bfv_runtime_.reset();
                        bfv_runtime_ = std::make_unique<PersistentGpuRuntime<heongpu::Scheme::BFV>>(
                            mega_ag_.parameter, all_galois_elts, task_identity, evaluation_context_identity,
                            evaluation_context_generation, gpu_device);
                    }
                    runtime = bfv_runtime_.get();
                }
                _run_mega_ag<heongpu::Scheme::BFV>(
                    input_args, output_args, mega_ag_, progress_cb, gpu_device, runtime,
                    evaluation_context_identity, evaluation_context_generation);
                break;
            }
            case Algo::ALGO_CKKS: {
                PersistentGpuRuntime<heongpu::Scheme::CKKS>* runtime = nullptr;
                if (cache_enabled) {
                    if (!ckks_runtime_ ||
                        !ckks_runtime_->matches(task_identity, parameter_identity, evaluation_context_identity,
                                                evaluation_context_generation, gpu_device)) {
                        ckks_runtime_.reset();
                        ckks_runtime_ = std::make_unique<PersistentGpuRuntime<heongpu::Scheme::CKKS>>(
                            mega_ag_.parameter, all_galois_elts, task_identity, evaluation_context_identity,
                            evaluation_context_generation, gpu_device);
                    }
                    runtime = ckks_runtime_.get();
                }
                _run_mega_ag<heongpu::Scheme::CKKS>(
                    input_args, output_args, mega_ag_, progress_cb, gpu_device, runtime,
                    evaluation_context_identity, evaluation_context_generation);
                break;
            }
            default: throw std::invalid_argument("algo not supported"); break;
        }

        CHECK(cudaDeviceSynchronize());

        return 0;
    }

protected:
    MegaAG mega_ag_;
    std::mutex key_cache_mutex_;
    uint64_t last_evaluation_context_identity_ = 0;
    uint64_t last_evaluation_context_handle_ = 0;
    uint64_t evaluation_context_generation_ = 0;
    std::unique_ptr<PersistentGpuRuntime<heongpu::Scheme::BFV>> bfv_runtime_;
    std::unique_ptr<PersistentGpuRuntime<heongpu::Scheme::CKKS>> ckks_runtime_;
};
};  // namespace gpu_wrapper

extern "C" {
fhe_task_handle create_fhe_gpu_task(const char* project_path) {
    gpu_wrapper::FheGpuTask* task = new gpu_wrapper::FheGpuTask(project_path);
    return (fhe_task_handle)task;
}

void release_fhe_gpu_task(fhe_task_handle handle) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    delete task;
}

void bind_gpu_task_abi_bridge_executors(fhe_task_handle handle, void* abi_export_executor, void* abi_import_executor) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    ExecutorFunc* export_executor = reinterpret_cast<ExecutorFunc*>(abi_export_executor);
    ExecutorFunc* import_executor = reinterpret_cast<ExecutorFunc*>(abi_import_executor);
    task->bind_abi_bridge_executors(*export_executor, *import_executor);
}

void bind_gpu_task_custom_executors(fhe_task_handle handle,
                                    const char** custom_types,
                                    void** executors,
                                    uint64_t n_executors) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    std::unordered_map<std::string, ExecutorFunc> custom_executors;
    for (uint64_t i = 0; i < n_executors; i++) {
        ExecutorFunc* executor_ptr = reinterpret_cast<ExecutorFunc*>(executors[i]);
        custom_executors[std::string(custom_types[i])] = *executor_ptr;
    }
    task->bind_custom_executors(custom_executors);
}

int run_fhe_gpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     progress_callback_t progress_cb,
                     void* user_data,
                     int gpu_device,
                     uint64_t evaluation_context_identity,
                     uint64_t evaluation_context_handle) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    gsl::span<CArgument> input_arg_span{input_args, n_in_args};
    gsl::span<CArgument> output_arg_span{output_args, n_out_args};

    ProgressCallback cb;
    if (progress_cb) {
        cb = [progress_cb, user_data](int completed, int total) { progress_cb(completed, total, user_data); };
    }
    return task->run(input_arg_span, output_arg_span, cb, gpu_device,
                     evaluation_context_identity, evaluation_context_handle);
}
}  // extern "C"
