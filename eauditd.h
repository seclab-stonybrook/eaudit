//cpp header file to declare classes and functions
//the logic is, we are only declaring one function
//to create logs. Python will only call this. Internally
//in the implementation, we'd use the recordString argument
//of this function to initialize auditconsumer, and call
//the ultimate printing function inside it. 

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
EXPORT_SYMBOL int logprinter(void* _x, void *log_buf, int sz);
EXPORT_SYMBOL size_t nread();
EXPORT_SYMBOL size_t nwritten();
EXPORT_SYMBOL size_t dowrite();
EXPORT_SYMBOL size_t calls();
EXPORT_SYMBOL size_t init_consumer(const char* capture_fn, const char* prt_fn,
                                     const char* record_fn);
EXPORT_SYMBOL size_t end_op();
#ifdef __cplusplus
}
#endif
