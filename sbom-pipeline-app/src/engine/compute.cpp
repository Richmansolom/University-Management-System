#include "engine/compute.h"

#include "math/series.h"
#include "util/string_util.h"

namespace example {
namespace engine {

std::string buildReport(int count) {
  auto series = example::math::fibonacci(count);
  auto seriesText = example::math::formatSeries(series);
  auto words = example::util::splitWords("Example Engine Report");
  return example::util::joinWith(words, " ") + ": [" + seriesText + "]";
}

}  // namespace engine
}  // namespace example
