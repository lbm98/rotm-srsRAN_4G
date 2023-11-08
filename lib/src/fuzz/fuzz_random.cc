#include <random>

#include "srsran/fuzz/fuzz_random.h"

static int fuzz_seed = 42;
static std::mt19937 fuzz_gen(fuzz_seed);


void fuzz_random_set_seed(int seed) {
  fuzz_seed = seed;
  fuzz_gen.seed(fuzz_seed);
}

int fuzz_random_get() {
  std::uniform_int_distribution<int> dist;
  return dist(fuzz_gen);
}

uint8_t fuzz_random_byte() {
  std::uniform_int_distribution<uint8_t> dist;
  return dist(fuzz_gen);
}

int fuzz_random_get_between(int min, int max) {
  std::uniform_int_distribution<int> dist(min, max);
  return dist(fuzz_gen);
}

int fuzz_random_enum_type(int nof_types) {
  return fuzz_random_get_between(0, nof_types-1);
}

bool fuzz_random_boolean() {
  return fuzz_random_get_between(0, 1) == 0;
}