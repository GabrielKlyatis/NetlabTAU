#pragma once

#include <iostream>
#include <array>
#include <vector>
#include <iterator>
#include <string>
#include <ctime>

void append_size_to_string(std::string& str, std::size_t value) {
	for (size_t i = 0; i < sizeof(std::size_t); ++i) {
		str.push_back(static_cast<char>((value >> (i * 8)) & 0xFF));
	}
}

/* Generates a random byte array. */
template <std::size_t N>
std::array<uint8_t, N> generate_random_bytes() {
	std::array<uint8_t, N> random_bytes;
	for (std::size_t i = 0; i < N; i++) {
		random_bytes[i] = rand() % 256;
	}
	return random_bytes;
}

uint32_t read_uint32_from_iterator(std::string::const_iterator& it) {
	uint32_t vector_size = 0;
	for (int i = 0; i <= 3; ++i) {
		vector_size |= static_cast<uint8_t>(*it) << (i * 8);
		++it;
	}
	return vector_size;
}

uint16_t read_uint16_from_iterator(std::string::const_iterator& it) {
	uint16_t vector_size = 0;
	for (int i = 0; i <= 1; ++i) {
		vector_size |= static_cast<uint8_t>(*it) << (i * 8);
		++it;
	}
	return vector_size;
}

