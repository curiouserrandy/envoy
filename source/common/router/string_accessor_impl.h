#pragma once

#include "envoy/router/string_accessor.h"

namespace Envoy {
namespace Router {

class StringAccessorImpl : public StringAccessor {
public:
  StringAccessorImpl(absl::string_view value) : value_(value) {}

  // StringAccessor
  ~StringAccessorImpl() override {}
  absl::string_view asString() const override { return value_; }

private:
  std::string value_;
};

} // namespace RequestInfo
} // namespace Envoy
