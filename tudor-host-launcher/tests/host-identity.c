#include <glib.h>

#include "host-identity.h"

static void test_identity_relations(void) {
    g_assert_cmpint(host_identity_compare(
        1, 5, "06cb-0081-reader-a", 1, 5, "06cb-0081-reader-a"),
        ==, HOST_IDENTITY_EXACT);
    g_assert_cmpint(host_identity_compare(
        1, 5, "06cb-0081-reader-a", 1, 6, "06cb-0081-reader-a"),
        ==, HOST_IDENTITY_SAME_STATE);
    g_assert_cmpint(host_identity_compare(
        1, 5, "06cb-0081-reader-a", 1, 5, "06cb-0081-reader-b"),
        ==, HOST_IDENTITY_SAME_USB);
    g_assert_cmpint(host_identity_compare(
        1, 5, "06cb-0081-reader-a", 2, 5, "06cb-0081-reader-b"),
        ==, HOST_IDENTITY_DISTINCT);
}

static void test_lifecycle_actions(void) {
    g_assert_cmpint(host_identity_launch_action(
        HOST_IDENTITY_DISTINCT, TRUE, FALSE), ==, HOST_LAUNCH_KEEP);
    g_assert_cmpint(host_identity_launch_action(
        HOST_IDENTITY_EXACT, TRUE, FALSE), ==, HOST_LAUNCH_REJECT);
    g_assert_cmpint(host_identity_launch_action(
        HOST_IDENTITY_EXACT, TRUE, TRUE), ==, HOST_LAUNCH_RETIRE);
    g_assert_cmpint(host_identity_launch_action(
        HOST_IDENTITY_EXACT, FALSE, FALSE), ==, HOST_LAUNCH_RETIRE);
    g_assert_cmpint(host_identity_launch_action(
        HOST_IDENTITY_SAME_STATE, TRUE, FALSE),
        ==, HOST_LAUNCH_RETIRE_NOTIFY);
    g_assert_cmpint(host_identity_launch_action(
        HOST_IDENTITY_SAME_USB, TRUE, FALSE),
        ==, HOST_LAUNCH_RETIRE_NOTIFY);
    g_assert_cmpint(host_identity_launch_action(
        HOST_IDENTITY_SAME_STATE, TRUE, TRUE), ==, HOST_LAUNCH_RETIRE);

    g_assert_true(host_identity_can_adopt(
        HOST_IDENTITY_EXACT, TRUE, TRUE));
    g_assert_false(host_identity_can_adopt(
        HOST_IDENTITY_EXACT, TRUE, FALSE));
    g_assert_false(host_identity_can_adopt(
        HOST_IDENTITY_SAME_STATE, TRUE, TRUE));
    g_assert_false(host_identity_can_adopt(
        HOST_IDENTITY_SAME_USB, TRUE, TRUE));
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/tudor/host-identity/relations", test_identity_relations);
    g_test_add_func("/tudor/host-identity/lifecycle", test_lifecycle_actions);
    return g_test_run();
}
