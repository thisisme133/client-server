#include "protected_function.hpp"

namespace protect {

bool FnProtectGlobal::request_and_wait(uint32_t marker_hash) {
    if (!requester_) return false;

    // Add pending request
    auto& pending = PendingRequests::instance();
    auto req = pending.add(marker_hash);

    // Send request to server
    if (!requester_->request_function(marker_hash)) {
        return false;
    }

    // Wait for response (timeout 5 seconds)
    return pending.wait_for(marker_hash, std::chrono::seconds(5));
}

} // namespace protect
