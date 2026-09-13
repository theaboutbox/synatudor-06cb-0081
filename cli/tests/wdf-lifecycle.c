#include <assert.h>
#include <stdatomic.h>
/* Include the private device layout to exercise real queue unlinking. */
#include "../../libtudor/src/winapi/wdf/device.c"

static unsigned int destroyed;
static atomic_uint actions;

static void destroy_object(struct wdf_object *obj) {
    destroyed++;
    wdf_cleanup_obj(obj);
    free(obj);
}

static struct wdf_object *new_object(struct wdf_object *parent) {
    struct wdf_object *obj = malloc(sizeof(*obj));
    assert(obj);
    wdf_create_obj(parent, obj, destroy_object, NULL);
    return obj;
}

static void count_action(struct wdf_object *obj) {
    (void)obj;
    atomic_fetch_add(&actions, 1);
}

static void *enqueue_actions(void *obj) {
    for(unsigned int i = 0; i < 2000; i++)
        wdf_evtqueue_enqueue(obj, count_action);
    return NULL;
}

int main(void) {
    struct wdf_object *parent = new_object(NULL);
    struct wdf_object *child = new_object(parent);
    new_object(parent);
    new_object(child);
    winwdf_destroy_object(parent);
    assert(destroyed == 4);

    struct winwdf_device dev = {0};
    assert(pthread_mutex_init(&dev.queues_lock, NULL) == 0);
    struct winwdf_queue *first = (void *)&dev;
    struct winwdf_queue *second = (void *)&destroyed;
    wdf_add_device_queue(&dev, first);
    wdf_add_device_queue(&dev, second);
    wdf_remove_device_queue(&dev, second);
    wdf_remove_device_queue(&dev, first);
    assert(dev.queues_head == NULL);
    assert(pthread_mutex_destroy(&dev.queues_lock) == 0);

    parent = new_object(NULL);
    pthread_t producer;
    assert(pthread_create(&producer, NULL, enqueue_actions, parent) == 0);
    for(unsigned int i = 0; i < 2000; i++) winwdf_event_queue_flush();
    assert(pthread_join(producer, NULL) == 0);
    winwdf_event_queue_flush();
    assert(atomic_load(&actions) == 2000);
    wdf_evtqueue_enqueue(parent, count_action);
    winwdf_destroy_object(parent);
    winwdf_event_queue_flush();
    assert(atomic_load(&actions) == 2000); /* deleted object's action is orphaned */
    return 0;
}
