#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" {

#include "utils.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char* str = strdup(provider.ConsumeRandomLengthString(1000).c_str());

    remove_path(str);

    free(str);
    return 0;
}
