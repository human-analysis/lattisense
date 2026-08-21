// Copyright 2024-2026 Alişah Özcan
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
// Developer: Alişah Özcan

#include <heongpu/heongpu.hpp>
#include <gtest/gtest.h>

template <typename T>
bool fix_point_equal(T input1, T input2, T epsilon = static_cast<T>(1e-4))
{
    return std::fabs(input1 - input2) < epsilon;
}

template <typename T>
bool fix_point_array_check(const std::vector<T>& array1,
                           const std::vector<T>& array2,
                           T epsilon = static_cast<T>(1e-4))
{
    if (array1.size() != array2.size())
    {
        return false;
    }

    for (size_t i = 0; i < array1.size(); ++i)
    {
        if (!fix_point_equal(array1[i], array2[i], epsilon))
        {
            return false;
        }
    }

    return true;
}

TEST(HEonGPU, CKKS_Ciphertext_Ciphertext_Addition)
{
    {
        size_t poly_modulus_degree = 4096;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes({40, 30, 30}, {40});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::Relinkey<heongpu::Scheme::CKKS> relin_key(context);
        keygen.generate_relin_key(relin_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 30);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C2(context);
        encryptor.encrypt(C2, P2);

        operators.add_inplace(C1, C2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 8192;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes({40, 30, 30, 30, 30}, {40});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::Relinkey<heongpu::Scheme::CKKS> relin_key(context);
        keygen.generate_relin_key(relin_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 30);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C2(context);
        encryptor.encrypt(C2, P2);

        operators.add_inplace(C1, C2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 16384;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes(
            {45, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35}, {45});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::Relinkey<heongpu::Scheme::CKKS> relin_key(context);
        keygen.generate_relin_key(relin_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 35);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C2(context);
        encryptor.encrypt(C2, P2);

        operators.add_inplace(C1, C2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 32768;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes({59, 40, 40, 40, 40, 40, 40, 40,
                                              40, 40, 40, 40, 40, 40, 40, 40,
                                              40, 40, 40},
                                             {59});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::Relinkey<heongpu::Scheme::CKKS> relin_key(context);
        keygen.generate_relin_key(relin_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 40);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C2(context);
        encryptor.encrypt(C2, P2);

        operators.add_inplace(C1, C2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 65536;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes(
            {59, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
             45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
             45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45},
            {59});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::Relinkey<heongpu::Scheme::CKKS> relin_key(context);
        keygen.generate_relin_key(relin_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 45);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C2(context);
        encryptor.encrypt(C2, P2);

        operators.add_inplace(C1, C2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }
}

TEST(HEonGPU, CKKS_Ciphertext_Plaintext_Addition)
{
    {
        size_t poly_modulus_degree = 4096;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes({40, 30, 30}, {40});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 30);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        operators.add_plain_inplace(C1, P2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 8192;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes({40, 30, 30, 30, 30}, {40});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 30);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        operators.add_plain_inplace(C1, P2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 16384;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes(
            {45, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35}, {45});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 35);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        operators.add_plain_inplace(C1, P2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 32768;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes({59, 40, 40, 40, 40, 40, 40, 40,
                                              40, 40, 40, 40, 40, 40, 40, 40,
                                              40, 40, 40},
                                             {59});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 40);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        operators.add_plain_inplace(C1, P2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();

    {
        size_t poly_modulus_degree = 65536;
        heongpu::HEContext<heongpu::Scheme::CKKS> context =
            heongpu::GenHEContext<heongpu::Scheme::CKKS>(
                heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(poly_modulus_degree);
        context->set_coeff_modulus_bit_sizes(
            {59, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
             45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45,
             45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45},
            {59});
        context->generate();

        heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
        keygen.generate_secret_key(secret_key);

        heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
        keygen.generate_public_key(public_key, secret_key);

        heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
        heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context,
                                                              public_key);
        heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context,
                                                              secret_key);
        heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                       encoder);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = poly_modulus_degree / 2;
        std::vector<double> message1(row_size, 0);
        std::vector<double> message2(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message1[i] = dis(gen);
            message2[i] = dis(gen);
        }

        std::vector<double> message_multiplication_result(row_size, 0);
        for (int i = 0; i < row_size; i++)
        {
            message_multiplication_result[i] = message1[i] + message2[i];
        }

        double scale = pow(2.0, 45);
        heongpu::Plaintext<heongpu::Scheme::CKKS> P1(context);
        encoder.encode(P1, message1, scale);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P2(context);
        encoder.encode(P2, message2, scale);

        heongpu::Ciphertext<heongpu::Scheme::CKKS> C1(context);
        encryptor.encrypt(C1, P1);

        operators.add_plain_inplace(C1, P2);

        heongpu::Plaintext<heongpu::Scheme::CKKS> P3(context);
        decryptor.decrypt(P3, C1);

        std::vector<double> gpu_result;
        encoder.decode(gpu_result, P3);

        cudaDeviceSynchronize();

        EXPECT_EQ(
            fix_point_array_check(message_multiplication_result, gpu_result),
            true);
    }

    cudaDeviceSynchronize();
}

TEST(HEonGPU, CKKS_CryptoFace_N65536_Q32_Addition)
{
    constexpr size_t poly_modulus_degree = 65536;
    const std::vector<Data64> q = {
        36028797019488257ULL,
        17592182243329ULL,
        17592180539393ULL,
        17592179097601ULL,
        17592178180097ULL,
        17592174247937ULL,
        17592173068289ULL,
        17592172412929ULL,
        17592167170049ULL,
        17592163368961ULL,
        17592162189313ULL,
        17592162058241ULL,
        17592160616449ULL,
        17592157863937ULL,
        17592155897857ULL,
        17592154980353ULL,
        17592152227841ULL,
        17592149999617ULL,
        17592149606401ULL,
        17592148688897ULL,
        36028797023420417ULL,
        36028797014376449ULL,
        36028797024206849ULL,
        36028797013327873ULL,
        36028797025124353ULL,
        36028797010444289ULL,
        36028797005856769ULL,
        36028797032202241ULL,
        72057594038321153ULL,
        72057594036879361ULL,
        72057594035306497ULL,
        72057594040680449ULL,
    };
    const std::vector<Data64> p = {
        2305843009211596801ULL,
        2305843009210023937ULL,
        2305843009208713217ULL,
    };

    auto context = heongpu::GenHEContext<heongpu::Scheme::CKKS>(
        heongpu::sec_level_type::none);
    context->set_poly_modulus_degree(poly_modulus_degree);
    context->set_slot_count(poly_modulus_degree / 2);
    context->set_coeff_modulus_values(q, p);
    context->generate();

    heongpu::HEKeyGenerator<heongpu::Scheme::CKKS> keygen(context);
    heongpu::Secretkey<heongpu::Scheme::CKKS> secret_key(context);
    keygen.generate_secret_key(secret_key);
    heongpu::Publickey<heongpu::Scheme::CKKS> public_key(context);
    keygen.generate_public_key(public_key, secret_key);

    heongpu::HEEncoder<heongpu::Scheme::CKKS> encoder(context);
    heongpu::HEEncryptor<heongpu::Scheme::CKKS> encryptor(context, public_key);
    heongpu::HEDecryptor<heongpu::Scheme::CKKS> decryptor(context, secret_key);
    heongpu::HEArithmeticOperator<heongpu::Scheme::CKKS> operators(context,
                                                                   encoder);

    const size_t slots = poly_modulus_degree / 2;
    std::vector<double> message1(slots), message2(slots), expected(slots);
    for (size_t i = 0; i < slots; ++i)
    {
        message1[i] = (static_cast<double>(i % 257) - 128.0) / 257.0;
        message2[i] = (static_cast<double>((i * 17) % 251) - 125.0) / 251.0;
        expected[i] = message1[i] + message2[i];
    }

    auto max_abs_error = [](const std::vector<double>& want,
                            const std::vector<double>& got) {
        if (want.size() != got.size())
        {
            return std::numeric_limits<double>::infinity();
        }
        double max_error = 0.0;
        for (size_t i = 0; i < want.size(); ++i)
        {
            max_error = std::max(max_error, std::abs(want[i] - got[i]));
        }
        return max_error;
    };

    constexpr double scale = 17592186044416.0;
    heongpu::Plaintext<heongpu::Scheme::CKKS> plain1(context), plain2(context);
    encoder.encode(plain1, message1, scale);
    encoder.encode(plain2, message2, scale);

    std::vector<double> decoded;
    encoder.decode(decoded, plain1);
    ASSERT_LT(max_abs_error(message1, decoded), 1e-4) << "encode/decode";

    heongpu::Ciphertext<heongpu::Scheme::CKKS> ciphertext(context);
    encryptor.encrypt(ciphertext, plain1);
    heongpu::Plaintext<heongpu::Scheme::CKKS> decrypted(context);
    decryptor.decrypt(decrypted, ciphertext);
    encoder.decode(decoded, decrypted);
    ASSERT_LT(max_abs_error(message1, decoded), 1e-3) << "encrypt/decrypt";

    operators.add_plain_inplace(ciphertext, plain2);
    decryptor.decrypt(decrypted, ciphertext);
    encoder.decode(decoded, decrypted);
    EXPECT_LT(max_abs_error(expected, decoded), 1e-3) << "ciphertext + plaintext";

    std::vector<double> expected_product(slots);
    for (size_t i = 0; i < slots; ++i)
    {
        expected_product[i] = message1[i] * message2[i];
    }
    heongpu::Plaintext<heongpu::Scheme::CKKS> ringt2(context);
    encoder.encode_ringt(ringt2, message2, scale);
    heongpu::Ciphertext<heongpu::Scheme::CKKS> ciphertext_product(context);
    encryptor.encrypt(ciphertext_product, plain1);
    operators.multiply_plain_inplace(ciphertext_product, ringt2);
    decryptor.decrypt(decrypted, ciphertext_product);
    encoder.decode(decoded, decrypted);
    EXPECT_LT(max_abs_error(expected_product, decoded), 1e-3)
        << "ciphertext * RingT plaintext";

    std::vector<int> conv0_shifts = {
        -8192, -4096, -2048, -1024, -32, -1, 1,
        32, 1024, 2048, 4096, 8192, 16384,
    };
    heongpu::Galoiskey<heongpu::Scheme::CKKS> galois_key(
        context, conv0_shifts);
    keygen.generate_galois_key(galois_key, secret_key);
    int target_level = 13;
    if (const char* requested_level = std::getenv("HEONGPU_TEST_LEVEL"))
    {
        target_level = std::atoi(requested_level);
    }
    for (const int shift : conv0_shifts)
    {
        heongpu::Ciphertext<heongpu::Scheme::CKKS> ciphertext_rotated(context);
        encryptor.encrypt(ciphertext_rotated, plain1);
        while (ciphertext_rotated.level() > target_level)
        {
            operators.mod_drop_inplace(ciphertext_rotated);
        }

        operators.rotate_rows(
            ciphertext_rotated, ciphertext_rotated, galois_key, shift);
        decryptor.decrypt(decrypted, ciphertext_rotated);
        encoder.decode(decoded, decrypted);
        std::vector<double> expected_rotated(slots);
        for (size_t i = 0; i < slots; ++i)
        {
            const auto source = static_cast<size_t>(
                (static_cast<long long>(i) + shift + slots) % slots);
            expected_rotated[i] = message1[source];
        }
        const double rotation_error = max_abs_error(expected_rotated, decoded);
        std::cout << "HEONGPU_TEST_LEVEL=" << target_level
                  << " shift=" << shift
                  << " rotation_max_abs_error=" << rotation_error << std::endl;
        EXPECT_LT(rotation_error, 1e-2)
            << "ciphertext rotation/key switching, shift=" << shift;
    }
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
