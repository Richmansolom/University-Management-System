#include "io/printer.h"

#include "engine/compute.h"

namespace example {
namespace io {

std::string renderOutput(int count) {
  return "Output => " + example::engine::buildReport(count);
}

}  // namespace io
}  // namespace example
