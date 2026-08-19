#pragma once

namespace d2r {

class RetcheckV2Adapter {
 public:
  static bool HasResolvedMetadata();
  static bool ValidateReadOnly();
};

}  // namespace d2r
