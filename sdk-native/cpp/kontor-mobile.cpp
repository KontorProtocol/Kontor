// Scaffolded by uniffi-bindgen-react-native, hand-maintained since (see
// generate-bindings.sh). The upstream template emitted an absolute path
// (`#include "/kontor_mobile.hpp"`) that can't compile; the header lives
// in this directory.
#include "kontor-mobile.h"
#include "kontor_mobile.hpp"

namespace kontormobile {
	using namespace facebook;

	uint8_t installRustCrate(jsi::Runtime &runtime, std::shared_ptr<react::CallInvoker> callInvoker) {
		NativeKontorMobile::registerModule(runtime, callInvoker);
		return true;
	}

	uint8_t cleanupRustCrate(jsi::Runtime &runtime) {
		return false;
	}
}