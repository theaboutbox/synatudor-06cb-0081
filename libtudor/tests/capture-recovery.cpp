#include <cstdio>

extern "C" int tudor_internal_test_capture_recovery(void);

int main(void) {
    int result = tudor_internal_test_capture_recovery();
    if(result != 0)
        std::fprintf(stderr, "capture recovery test failed at check %d\n",
                     result);
    return result;
}
