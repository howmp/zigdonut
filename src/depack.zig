pub const struct_APDSTATE = extern struct {
    source: [*c]const u8,
    destination: [*c]u8,
    tag: c_uint,
    bitcount: c_uint,
};
pub inline fn aP_depack(arg_source: ?*const anyopaque, arg_destination: ?*anyopaque) void {
    var source = arg_source;
    var destination = arg_destination;
    var ud: struct_APDSTATE = undefined;
    var offs: c_uint = undefined;
    var len: c_uint = undefined;
    var R0: c_uint = undefined;
    var LWM: c_uint = undefined;
    var done: c_int = undefined;
    var i: c_int = undefined;
    ud.source = @as([*c]const u8, @ptrCast(@alignCast(source)));
    ud.destination = @as([*c]u8, @ptrCast(@alignCast(destination)));
    ud.bitcount = 0;
    R0 = @as(c_uint, @bitCast(-@as(c_int, 1)));
    LWM = 0;
    done = 0;
    (blk: {
        const ref = &ud.destination;
        const tmp = ref.*;
        ref.* += 1;
        break :blk tmp;
    }).* = (blk: {
        const ref = &ud.source;
        const tmp = ref.*;
        ref.* += 1;
        break :blk tmp;
    }).*;
    while (!(done != 0)) {
        if (aP_getbit(&ud) != 0) {
            if (aP_getbit(&ud) != 0) {
                if (aP_getbit(&ud) != 0) {
                    offs = 0;
                    {
                        i = 4;
                        while (i != 0) : (i -= 1) {
                            offs = (offs << @intCast(1)) +% aP_getbit(&ud);
                        }
                    }
                    if (offs != 0) {
                        ud.destination.* = (ud.destination - offs).*;
                        ud.destination += 1;
                    } else {
                        (blk: {
                            const ref = &ud.destination;
                            const tmp = ref.*;
                            ref.* += 1;
                            break :blk tmp;
                        }).* = 0;
                    }
                    LWM = 0;
                } else {
                    offs = @as(c_uint, @bitCast(@as(c_uint, (blk: {
                        const ref = &ud.source;
                        const tmp = ref.*;
                        ref.* += 1;
                        break :blk tmp;
                    }).*)));
                    len = @as(c_uint, @bitCast(@as(c_int, 2))) +% (offs & @as(c_uint, @bitCast(@as(c_int, 1))));
                    offs >>= @intCast(@as(c_int, 1));
                    if (offs != 0) {
                        while (len != 0) : (len -%= 1) {
                            ud.destination.* = (ud.destination - offs).*;
                            ud.destination += 1;
                        }
                    } else {
                        done = 1;
                    }
                    R0 = offs;
                    LWM = 1;
                }
            } else {
                offs = aP_getgamma(&ud);
                if ((LWM == @as(c_uint, @bitCast(@as(c_int, 0)))) and (offs == @as(c_uint, @bitCast(@as(c_int, 2))))) {
                    offs = R0;
                    len = aP_getgamma(&ud);
                    while (len != 0) : (len -%= 1) {
                        ud.destination.* = (ud.destination - offs).*;
                        ud.destination += 1;
                    }
                } else {
                    if (LWM == @as(c_uint, @bitCast(@as(c_int, 0)))) {
                        offs -%= @as(c_uint, @bitCast(@as(c_int, 3)));
                    } else {
                        offs -%= @as(c_uint, @bitCast(@as(c_int, 2)));
                    }
                    offs <<= @intCast(@as(c_int, 8));
                    offs +%= @as(c_uint, @bitCast(@as(c_uint, (blk: {
                        const ref = &ud.source;
                        const tmp = ref.*;
                        ref.* += 1;
                        break :blk tmp;
                    }).*)));
                    len = aP_getgamma(&ud);
                    if (offs >= @as(c_uint, @bitCast(@as(c_int, 32000)))) {
                        len +%= 1;
                    }
                    if (offs >= @as(c_uint, @bitCast(@as(c_int, 1280)))) {
                        len +%= 1;
                    }
                    if (offs < @as(c_uint, @bitCast(@as(c_int, 128)))) {
                        len +%= @as(c_uint, @bitCast(@as(c_int, 2)));
                    }
                    while (len != 0) : (len -%= 1) {
                        ud.destination.* = (ud.destination - offs).*;
                        ud.destination += 1;
                    }
                    R0 = offs;
                }
                LWM = 1;
            }
        } else {
            (blk: {
                const ref = &ud.destination;
                const tmp = ref.*;
                ref.* += 1;
                break :blk tmp;
            }).* = (blk: {
                const ref = &ud.source;
                const tmp = ref.*;
                ref.* += 1;
                break :blk tmp;
            }).*;
            LWM = 0;
        }
    }
}
inline fn aP_getbit(arg_ud: [*c]struct_APDSTATE) c_uint {
    var ud = arg_ud;
    var bit: c_uint = undefined;
    if (!((blk: {
        const ref = &ud.*.bitcount;
        const tmp = ref.*;
        ref.* -%= 1;
        break :blk tmp;
    }) != 0)) {
        ud.*.tag = @as(c_uint, @bitCast(@as(c_uint, (blk: {
            const ref = &ud.*.source;
            const tmp = ref.*;
            ref.* += 1;
            break :blk tmp;
        }).*)));
        ud.*.bitcount = 7;
    }
    bit = (ud.*.tag >> @intCast(7)) & @as(c_uint, @bitCast(@as(c_int, 1)));
    ud.*.tag <<= @intCast(@as(c_int, 1));
    return bit;
}
inline fn aP_getgamma(arg_ud: [*c]struct_APDSTATE) c_uint {
    var ud = arg_ud;
    var result: c_uint = 1;
    while (true) {
        result = (result << @intCast(1)) +% aP_getbit(ud);
        if (!(aP_getbit(ud) != 0)) break;
    }
    return result;
}
