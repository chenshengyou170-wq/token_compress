#ifndef CODEXSCOPE_FUNCTION_TRACE_H
#define CODEXSCOPE_FUNCTION_TRACE_H

#if defined(__GNUC__) || defined(__clang__)
#define CODEXSCOPE_NOINSTRUMENT __attribute__((no_instrument_function))
#else
#define CODEXSCOPE_NOINSTRUMENT
#endif

#ifdef __cplusplus
extern "C" {
#endif

void __cyg_profile_func_enter(void *function, void *call_site)
    CODEXSCOPE_NOINSTRUMENT;
void __cyg_profile_func_exit(void *function, void *call_site)
    CODEXSCOPE_NOINSTRUMENT;

#ifdef __cplusplus
}
#endif

#endif
