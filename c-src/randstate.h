#pragma once

#include <gmp.h>
#include <stdint.h>

extern gmp_randstate_t state;

void randstate_init(uint64_t seed);

void randstate_clear(void);
