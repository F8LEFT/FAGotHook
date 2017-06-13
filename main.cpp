

#ifndef FA_STATIC

#include <jni.h>
#include "MinAndroidDef.h"

void test();

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
    test();
    return JNI_VERSION_1_6;
}

#include <dlfcn.h>
#include <stdio.h>
#include "FAGotHook.h"

void myFopen() {
    FLOGD(My Fopen has been invoked);
}

void test() {
    auto libc = dlopen("libc.so", RTLD_NOW);
    auto pfopen = dlsym(libc, "fopen");

    FAGotHook::Config cfg;
    cfg.check_ehdr = false;
    cfg.unprotect_got_memory = true;

    FAGotHook faGotHook("libFAGotHook.so", &cfg);
    if(faGotHook.is_valid()) {
        faGotHook.rebindFunc((Elf_Addr) pfopen, (Elf_Addr) myFopen);
    }

    fopen("/data/data/f8left.fagothook/cachefile", "r");

}


#endif