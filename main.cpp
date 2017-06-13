

#ifndef FA_STATIC

#include <jni.h>
#include "MinAndroidDef.h"
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{

    JNIEnv *env = nullptr;
    jint result = -1;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        FLOGE(This jni version is not supported);
        return -1;
    }

    FLOGD(FAGotHook.so load success);
    FLOGD(current JNI Version %d, JNI_VERSION_1_6);
    return JNI_VERSION_1_6;
}

#endif