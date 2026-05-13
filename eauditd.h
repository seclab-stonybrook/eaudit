#pragma once
#ifdef __cplusplus
    #include <cstdint>
#else
    #include <stdint.h>
    #include <stdbool.h>
#endif

#ifdef _WIN32
    #ifdef BUILD_CBMP
        #define EXPORT_SYMBOL __declspec(dllexport)
    #else
        #define EXPORT_SYMBOL __declspec(dllimport)
    #endif
#else
     #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif
EXPORT_SYMBOL long init_consumer(int argc, const char* argv[]);
EXPORT_SYMBOL long logprinter(void* _x, void *log_buf, int sz);
EXPORT_SYMBOL long dowrite(); // Same return value as ncalls
EXPORT_SYMBOL long end_op();

EXPORT_SYMBOL long calls();   // Returns the number of calls to logprinter
EXPORT_SYMBOL long nread();
EXPORT_SYMBOL long nwritten();
#ifdef __cplusplus
}
#endif
