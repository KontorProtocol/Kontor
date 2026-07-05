# Consumer ProGuard/R8 rules for @kontor/sdk-native, applied to the host
# app's release build (referenced by consumerProguardFiles in build.gradle).
#
# The JSI Turbo Module reaches native code through JNI: KontorMobileModule's
# `external` methods are resolved by name against cpp-adapter.cpp, and the
# module/package classes are instantiated reflectively by React Native. R8
# must not rename or strip them.

# Keep JNI native method entry points (name-matched from C++).
-keepclasseswithmembernames,includedescriptorclasses class com.kontor.sdknative.** {
    native <methods>;
}

# Keep the TurboModule + package classes RN loads reflectively.
-keep class com.kontor.sdknative.KontorMobileModule { *; }
-keep class com.kontor.sdknative.KontorMobilePackage { *; }
