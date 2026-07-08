// Scaffolded by uniffi-bindgen-react-native, hand-maintained since (see
// generate-bindings.sh). The upstream template emitted an absolute path
// (`#include "/kontor_sdk_native.hpp"`) that can't compile; the header lives
// in this directory.
#include "kontor-sdk-native.h"
#include "kontor_sdk_native.hpp"

namespace kontormobile {
	using namespace facebook;

	uint8_t installRustCrate(jsi::Runtime &runtime, std::shared_ptr<react::CallInvoker> callInvoker) {
		NativeKontorSdkNative::registerModule(runtime, callInvoker);
		return true;
	}

	uint8_t cleanupRustCrate(jsi::Runtime &runtime) {
		NativeKontorSdkNative::unregisterModule(runtime);
		return true;
	}
}