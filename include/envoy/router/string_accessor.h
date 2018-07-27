#pragma once

#include "envoy/common/pure.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Router {

/**
 * Contains a string in a form which is usable with DynamicMetadata and
 * allows lazy evaluation if needed. All values meant to be accessible to the
 * custom request/response header mechanism must use this type.
 */
class StringAccessor {
public:
  virtual ~StringAccessor(){};

  /**
   * @return the string the accessor represents.
   */
  virtual absl::string_view asString() const PURE;
};

} // namespace Router
} // namespace Envoy
