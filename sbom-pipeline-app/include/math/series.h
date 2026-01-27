#pragma once

#include <string>
#include <vector>

namespace example {
namespace math {

std::vector<int> fibonacci(int count);
std::string formatSeries(const std::vector<int>& values);

}  // namespace math
}  // namespace example
