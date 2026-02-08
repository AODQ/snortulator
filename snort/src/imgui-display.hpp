#pragma once

#include "device.hpp"

namespace snort {

void displayInitialize(snort::Device const & device);
void displayFrameBegin(snort::Device const & device);
void displayFrameEnd(snort::Device const & device);

} // namespace snort
