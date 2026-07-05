// Expo config plugin for @kontor/sdk-native.
//
// The native binaries this package ships are prebuilt (an xcframework +
// jniLibs, produced by build-mobile.sh). A consumer Expo app just links
// them — but the link only succeeds if the app's native build settings
// are at least as high as what the binaries were compiled against:
//
//   • iOS  — the xcframework is built with IPHONEOS_DEPLOYMENT_TARGET=15.1
//            (blst's C objects reference symbols like ___chkstk_darwin that
//            don't exist below that; a lower app target fails the cdylib
//            link). Mirrors .github/workflows/mobile.yml.
//   • Android — the .so's are built for API platform 24 (build-mobile.sh
//            ANDROID_PLATFORM), so the app's minSdkVersion must be ≥ 24.
//
// This plugin raises those two floors during `expo prebuild` so consumers
// don't have to touch a Podfile or build.gradle. It only ever raises the
// values — an app already targeting a higher iOS/Android version keeps it.
//
// `expo/config-plugins` is re-exported by `expo`, which the consumer app
// already depends on, so this package needs no extra dependency for it.
const {
  withPodfileProperties,
  withGradleProperties,
  createRunOncePlugin,
} = require('expo/config-plugins');

const pkg = require('./package.json');

// Keep in sync with build-mobile.sh / mobile.yml.
const IOS_DEPLOYMENT_TARGET = '15.1';
const ANDROID_MIN_SDK = 24;

// "15.1" → 15001, so "16.0" (16000) reads as higher and is left untouched.
const iosVersionRank = (v) => {
  const [major = 0, minor = 0] = String(v).split('.').map(Number);
  return major * 1000 + minor;
};

const withIosDeploymentTarget = (config) =>
  withPodfileProperties(config, (cfg) => {
    const current = cfg.modResults['ios.deploymentTarget'];
    if (!current || iosVersionRank(current) < iosVersionRank(IOS_DEPLOYMENT_TARGET)) {
      cfg.modResults['ios.deploymentTarget'] = IOS_DEPLOYMENT_TARGET;
    }
    return cfg;
  });

const withAndroidMinSdk = (config) =>
  withGradleProperties(config, (cfg) => {
    const key = 'android.minSdkVersion';
    const existing = cfg.modResults.find(
      (item) => item.type === 'property' && item.key === key,
    );
    if (existing) {
      if (Number(existing.value) < ANDROID_MIN_SDK) {
        existing.value = String(ANDROID_MIN_SDK);
      }
    } else {
      cfg.modResults.push({ type: 'property', key, value: String(ANDROID_MIN_SDK) });
    }
    return cfg;
  });

const withKontorSdkNative = (config) =>
  withAndroidMinSdk(withIosDeploymentTarget(config));

module.exports = createRunOncePlugin(withKontorSdkNative, pkg.name, pkg.version);
