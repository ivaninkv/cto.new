const std = @import("std");
const net = std.net;
const mem = std.mem;
const fmt = std.fmt;
const Thread = std.Thread;

const Config = struct {
    hosts: []const u8,
    ports: []const u8 = "22,80,443",
    workers: u32 = 100,
    help: bool = false,
};

const ScanJob = struct {
    host: []const u8,
    port: u16,
};

const ScanResult = struct {
    host: []const u8,
    port: u16,
    is_open: bool,
};

const JobQueue = struct {
    jobs: std.ArrayList(ScanJob),
    mutex: Thread.Mutex,
    current_index: usize,

    fn init(allocator: mem.Allocator) JobQueue {
        return .{
            .jobs = std.ArrayList(ScanJob).init(allocator),
            .mutex = Thread.Mutex{},
            .current_index = 0,
        };
    }

    fn deinit(self: *JobQueue) void {
        self.jobs.deinit();
    }

    fn getNextJob(self: *JobQueue) ?ScanJob {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.current_index >= self.jobs.items.len) {
            return null;
        }

        const job = self.jobs.items[self.current_index];
        self.current_index += 1;
        return job;
    }
};

const ResultQueue = struct {
    results: std.ArrayList(ScanResult),
    mutex: Thread.Mutex,

    fn init(allocator: mem.Allocator) ResultQueue {
        return .{
            .results = std.ArrayList(ScanResult).init(allocator),
            .mutex = Thread.Mutex{},
        };
    }

    fn deinit(self: *ResultQueue) void {
        self.results.deinit();
    }

    fn addResult(self: *ResultQueue, result: ScanResult) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.results.append(result);
    }
};

fn printHelp() void {
    const help_text =
        \\Port Scanner - A simple CLI port scanner written in Zig
        \\
        \\Usage: port-scanner [options]
        \\
        \\Options:
        \\  -s, --hosts <string>    Hosts to scan (comma-separated, supports CIDR notation)
        \\                          Examples: scanme.nmap.org,example.com,192.168.1.0/24
        \\                          Required
        \\
        \\  -p, --ports <string>    Ports to scan (comma-separated, supports ranges)
        \\                          Examples: 1-1024,6443,8443
        \\                          Default: 22,80,443
        \\
        \\  -w, --workers <int>     Number of worker threads for parallel scanning
        \\                          Default: 100
        \\
        \\  -h, --help              Show this help message
        \\
        \\Examples:
        \\  port-scanner -s scanme.nmap.org -p 22,80,443
        \\  port-scanner -s 192.168.1.0/24 -p 1-1024 -w 200
        \\  port-scanner --hosts example.com --ports 80,443,8080 --workers 50
        \\
    ;
    std.debug.print("{s}\n", .{help_text});
}

fn parseArgs(allocator: mem.Allocator) !Config {
    var config = Config{ .hosts = "" };
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip();

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            config.help = true;
            return config;
        } else if (mem.eql(u8, arg, "-s") or mem.eql(u8, arg, "--hosts")) {
            if (args.next()) |value| {
                config.hosts = value;
            } else {
                std.debug.print("Error: --hosts requires a value\n", .{});
                return error.InvalidArgument;
            }
        } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--ports")) {
            if (args.next()) |value| {
                config.ports = value;
            } else {
                std.debug.print("Error: --ports requires a value\n", .{});
                return error.InvalidArgument;
            }
        } else if (mem.eql(u8, arg, "-w") or mem.eql(u8, arg, "--workers")) {
            if (args.next()) |value| {
                config.workers = try fmt.parseInt(u32, value, 10);
            } else {
                std.debug.print("Error: --workers requires a value\n", .{});
                return error.InvalidArgument;
            }
        } else {
            std.debug.print("Error: Unknown argument '{s}'\n", .{arg});
            return error.InvalidArgument;
        }
    }

    if (!config.help and config.hosts.len == 0) {
        std.debug.print("Error: --hosts is required\n\n", .{});
        printHelp();
        return error.InvalidArgument;
    }

    return config;
}

fn parsePorts(allocator: mem.Allocator, port_str: []const u8) !std.ArrayList(u16) {
    var ports = std.ArrayList(u16).init(allocator);
    errdefer ports.deinit();

    var iter = mem.split(u8, port_str, ",");
    while (iter.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;

        if (mem.indexOf(u8, trimmed, "-")) |dash_pos| {
            const start = try fmt.parseInt(u16, trimmed[0..dash_pos], 10);
            const end = try fmt.parseInt(u16, trimmed[dash_pos + 1 ..], 10);

            if (start > end) {
                std.debug.print("Error: Invalid port range {d}-{d}\n", .{ start, end });
                return error.InvalidRange;
            }

            var port = start;
            while (port <= end) : (port += 1) {
                try ports.append(port);
            }
        } else {
            const port = try fmt.parseInt(u16, trimmed, 10);
            try ports.append(port);
        }
    }

    return ports;
}

fn parseHosts(allocator: mem.Allocator, host_str: []const u8) !std.ArrayList([]const u8) {
    var hosts = std.ArrayList([]const u8).init(allocator);
    errdefer hosts.deinit();

    var iter = mem.split(u8, host_str, ",");
    while (iter.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;

        if (mem.indexOf(u8, trimmed, "/")) |_| {
            const cidr_hosts = try expandCIDR(allocator, trimmed);
            defer cidr_hosts.deinit();
            for (cidr_hosts.items) |host| {
                try hosts.append(host);
            }
        } else {
            const host_copy = try allocator.dupe(u8, trimmed);
            try hosts.append(host_copy);
        }
    }

    return hosts;
}

fn expandCIDR(allocator: mem.Allocator, cidr: []const u8) !std.ArrayList([]const u8) {
    var hosts = std.ArrayList([]const u8).init(allocator);
    errdefer hosts.deinit();

    const slash_pos = mem.indexOf(u8, cidr, "/") orelse return error.InvalidCIDR;
    const ip_str = cidr[0..slash_pos];
    const prefix_len = try fmt.parseInt(u8, cidr[slash_pos + 1 ..], 10);

    if (prefix_len > 32) {
        std.debug.print("Error: Invalid CIDR prefix length {d}\n", .{prefix_len});
        return error.InvalidCIDR;
    }

    var octets: [4]u8 = undefined;
    var octet_iter = mem.split(u8, ip_str, ".");
    var i: usize = 0;
    while (octet_iter.next()) |octet_str| : (i += 1) {
        if (i >= 4) return error.InvalidIP;
        octets[i] = try fmt.parseInt(u8, octet_str, 10);
    }
    if (i != 4) return error.InvalidIP;

    const base_ip: u32 = (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);

    const host_bits: u5 = @intCast(32 - prefix_len);
    const num_hosts: u32 = if (host_bits == 0) 1 else @as(u32, 1) << host_bits;
    const network_mask: u32 = if (prefix_len == 0) 0 else ~(@as(u32, 0xFFFFFFFF) >> @intCast(prefix_len));
    const network_addr = base_ip & network_mask;

    const max_hosts: u32 = if (num_hosts > 254) 254 else num_hosts;
    const start_offset: u32 = if (prefix_len < 31) 1 else 0;

    var offset: u32 = start_offset;
    while (offset < max_hosts) : (offset += 1) {
        const ip = network_addr + offset;
        const ip_string = try fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF,
        });
        try hosts.append(ip_string);
    }

    return hosts;
}

fn isHostAvailable(host: []const u8, timeout_ms: u64) bool {
    const ports_to_try = [_]u16{ 80, 443, 22, 21, 25 };

    for (ports_to_try) |port| {
        if (scanPort(host, port, timeout_ms)) {
            return true;
        }
    }

    return false;
}

fn scanPort(host: []const u8, port: u16, timeout_ms: u64) bool {
    _ = timeout_ms;
    
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const address_list = net.getAddressList(allocator, host, port) catch {
        return false;
    };
    defer address_list.deinit();

    if (address_list.addrs.len == 0) {
        return false;
    }

    const addr = address_list.addrs[0];
    
    const sock = std.posix.socket(
        addr.any.family,
        std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO.TCP,
    ) catch {
        return false;
    };
    defer std.posix.close(sock);

    _ = std.posix.connect(sock, &addr.any, addr.getOsSockLen()) catch |err| {
        if (err != error.WouldBlock) {
            return false;
        }
    };

    var poll_fds = [_]std.posix.pollfd{.{
        .fd = sock,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};

    const result = std.posix.poll(&poll_fds, 1000) catch {
        return false;
    };

    if (result == 0) {
        return false;
    }

    if (poll_fds[0].revents & std.posix.POLL.OUT != 0) {
        return true;
    }

    return false;
}

fn workerThread(job_queue: *JobQueue, result_queue: *ResultQueue) void {
    while (job_queue.getNextJob()) |job| {
        const is_open = scanPort(job.host, job.port, 1000);
        const result = ScanResult{
            .host = job.host,
            .port = job.port,
            .is_open = is_open,
        };
        result_queue.addResult(result) catch {};
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parseArgs(allocator) catch |err| {
        if (err == error.InvalidArgument) {
            std.process.exit(1);
        }
        return err;
    };

    if (config.help) {
        printHelp();
        return;
    }

    const hosts = try parseHosts(allocator, config.hosts);
    defer {
        for (hosts.items) |host| {
            allocator.free(host);
        }
        hosts.deinit();
    }

    const ports = try parsePorts(allocator, config.ports);
    defer ports.deinit();

    std.debug.print("Starting port scan...\n", .{});
    std.debug.print("Hosts: {d}, Ports: {d}, Workers: {d}\n\n", .{ hosts.items.len, ports.items.len, config.workers });

    var available_hosts = std.ArrayList([]const u8).init(allocator);
    defer available_hosts.deinit();

    for (hosts.items) |host| {
        if (isHostAvailable(host, 1000)) {
            try available_hosts.append(host);
        } else {
            std.debug.print("{s} - HOST UNREACHABLE\n", .{host});
        }
    }

    if (available_hosts.items.len == 0) {
        std.debug.print("\nNo hosts are available for scanning.\n", .{});
        return;
    }

    var job_queue = JobQueue.init(allocator);
    defer job_queue.deinit();

    for (available_hosts.items) |host| {
        for (ports.items) |port| {
            try job_queue.jobs.append(.{
                .host = host,
                .port = port,
            });
        }
    }

    var result_queue = ResultQueue.init(allocator);
    defer result_queue.deinit();

    const worker_count = @min(config.workers, @as(u32, @intCast(job_queue.jobs.items.len)));
    const threads = try allocator.alloc(Thread, worker_count);
    defer allocator.free(threads);

    for (threads) |*thread| {
        thread.* = try Thread.spawn(.{}, workerThread, .{ &job_queue, &result_queue });
    }

    for (threads) |thread| {
        thread.join();
    }

    std.debug.print("\n=== Scan Results ===\n", .{});
    for (result_queue.results.items) |result| {
        const status = if (result.is_open) "OPEN" else "CLOSED";
        std.debug.print("{s}:{d} - {s}\n", .{ result.host, result.port, status });
    }

    const open_count = blk: {
        var count: usize = 0;
        for (result_queue.results.items) |result| {
            if (result.is_open) count += 1;
        }
        break :blk count;
    };

    std.debug.print("\nTotal scanned: {d}, Open: {d}, Closed: {d}\n", .{
        result_queue.results.items.len,
        open_count,
        result_queue.results.items.len - open_count,
    });
}
