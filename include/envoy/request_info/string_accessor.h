#pragma once

#include "envoy/common/pure.h"
#include "envoy/request_info/dynamic_metadata.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace RequestInfo {

/**
 * Contains a string in a form which is usable with DynamicMetadata and
 * allows lazy evaluation if needed. All values meant to be accessible to the
 * custom request/response header mechanism and access logging must use this type.
 */
class StringAccessor : public ::Envoy::RequestInfo::DynamicMetadata::Object {
public:
  /**
   * @return the string the accessor represents.
   */
  virtual absl::string_view asString() const PURE;
};

} // namespace RequestInfo
} // namespace Envoy
