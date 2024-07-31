#include "tls_utils.hpp"

void append_size_to_string(std::string& str, std::size_t value) {
	for (size_t i = 0; i < sizeof(std::size_t); ++i) {
		str.push_back(static_cast<char>((value >> (i * 8)) & 0xFF));
	}
}

template <std::size_t N>
std::array<uint8_t, N> generate_random_bytes() {
	std::array<uint8_t, N> random_bytes;
	for (std::size_t i = 0; i < N; i++) {
		random_bytes[i] = rand() % MODULO_VALUE;
	}
	return random_bytes;
}

