void fuzz_random_set_seed(int seed);
int fuzz_random_get();
uint8_t fuzz_random_byte();
int fuzz_random_get_between(int min, int max);
int fuzz_random_enum_type(int nof_types);
bool fuzz_random_boolean();