#include "common/request_info/dynamic_metadata_impl.h"

#include "envoy/common/exception.h"

namespace Envoy {
namespace RequestInfo {

void DynamicMetadataImpl::setData(absl::string_view data_name,
                                  std::unique_ptr<DynamicMetadataObject>&& data) {
  if (data_storage_.find(data_name) != data_storage_.end()) {
    throw EnvoyException("DynamicMetadata::setData<T> called twice with same name.");
  }
  data_storage_[static_cast<std::string>(data_name)] = std::move(data);
}

bool DynamicMetadataImpl::hasDataWithName(absl::string_view data_name) const {
  return data_storage_.count(data_name) > 0;
}

const DynamicMetadata::DynamicMetadataObject*
DynamicMetadataImpl::getDataGeneric(absl::string_view data_name) const {
  const auto& it = data_storage_.find(data_name);

  if (it == data_storage_.end()) {
    throw EnvoyException("DynamicMetadata::getData<T> called for unknown data name.");
  }
  return it->second.get();
}

} // namespace RequestInfo
} // namespace Envoy
