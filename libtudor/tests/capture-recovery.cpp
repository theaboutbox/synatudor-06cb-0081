#include <cstdio>

extern "C" int tudor_internal_test_capture_recovery(void);
extern "C" int tudor_internal_test_buffered_input(void);
extern "C" int tudor_internal_test_ownership_failure_guard(void);
extern "C" int tudor_internal_test_ownership_failure_marker(void);
extern "C" int tudor_internal_test_ownership_reset_dispatch(void);
int pairing_layout_test(const char *driver_path);

int main(int argc, char **argv) {
    if(argc == 2) return pairing_layout_test(argv[1]);
    if(argc != 1) return 1;
    int result = tudor_internal_test_buffered_input();
    if(result != 0) {
        std::fprintf(stderr, "buffered input lifetime test failed at check %d\n", result);
        return 10 + result;
    }
    result = tudor_internal_test_capture_recovery();
    if(result != 0) {
        std::fprintf(stderr, "capture recovery test failed at check %d\n",
                     result);
        return result;
    }

    result = tudor_internal_test_ownership_failure_guard();
    if(result != 0) {
        std::fprintf(stderr,
                     "ownership failure guard test failed at check %d\n",
                     result);
        return 100 + result;
    }

    result = tudor_internal_test_ownership_failure_marker();
    if(result != 0) {
        std::fprintf(stderr,
                     "ownership failure marker test failed at check %d\n",
                     result);
        return 200 + result;
    }

    result = tudor_internal_test_ownership_reset_dispatch();
    if(result != 0) {
        std::fprintf(stderr,
                     "ownership reset dispatch test failed at check %d\n",
                     result);
        return 300 + result;
    }
    return 0;
}
