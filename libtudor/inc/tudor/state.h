#ifndef LIBTUDOR_TUDOR_STATE_H
#define LIBTUDOR_TUDOR_STATE_H

enum tudor_state_value_type {
    TUDOR_STATE_VALUE_UINT32 = 1,
    TUDOR_STATE_VALUE_BLOB = 2,
    /* One byte on the wire: 0 for false or 1 for true. */
    TUDOR_STATE_VALUE_BOOL = 3
};

#endif
