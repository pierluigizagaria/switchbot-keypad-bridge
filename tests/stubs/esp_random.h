#pragma once

#include <cstdint>

uint32_t esp_random();

#include <cstddef>
extern "C" void esp_fill_random(void *data, size_t size);
