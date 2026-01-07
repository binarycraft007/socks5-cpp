const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const gtest_dep = b.dependency("googletest", .{});

    const gtest_main = b.addLibrary(.{
        .name = "asio",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });
    gtest_main.root_module.addCSourceFiles(.{
        .root = gtest_dep.path("googletest/src"),
        .files = &.{
            "gtest-all.cc",
            "gtest_main.cc",
        },
        .language = .cpp,
        .flags = &.{"-std=c++23"},
    });
    gtest_main.root_module.addIncludePath(gtest_dep.path("googletest"));
    gtest_main.root_module.addIncludePath(gtest_dep.path("googletest/include"));
    gtest_main.installHeadersDirectory(gtest_dep.path("googletest/include"), "", .{});

    const asio_dep = b.dependency("asio", .{});

    const asio = b.addLibrary(.{
        .name = "asio",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });

    // Define macros on the root module
    asio.root_module.addCMacro("ASIO_STANDALONE", "1");
    asio.root_module.addCMacro("ASIO_SEPARATE_COMPILATION", "1");
    asio.root_module.addCMacro("ASIO_ENABLE_CANCELIO", "1");
    asio.root_module.addCMacro("_REENTRANT", "1");

    // Add include directory
    asio.root_module.addIncludePath(asio_dep.path("asio/include"));
    asio.root_module.addIncludePath(asio_dep.path("asio/include"));

    // Add C++ source files
    asio.root_module.addCSourceFile(.{
        .file = asio_dep.path("asio/src/asio.cpp"),
        .flags = &.{"-std=gnu++23"},
        .language = .cpp,
    });

    // Link system libraries
    switch (target.result.os.tag) {
        .linux => {
            asio.root_module.linkSystemLibrary("pthread", .{});
        },
        .windows => {
            // Essential Winsock libraries
            asio.root_module.linkSystemLibrary("ws2_32", .{});
            asio.root_module.linkSystemLibrary("mswsock", .{});
            asio.root_module.linkSystemLibrary("bcrypt", .{});
        },
        .macos => {},
        else => {
            // Fallback for other POSIX systems
            asio.root_module.linkSystemLibrary("pthread", .{});
        },
    }

    asio.installHeadersDirectory(asio_dep.path("asio/include"), "", .{
        .include_extensions = &.{ ".hpp", "ipp" },
    });

    const lib = b.addLibrary(.{
        .name = "socks5",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });
    lib.root_module.addIncludePath(b.path("include"));
    lib.root_module.linkLibrary(asio);
    lib.root_module.addCSourceFiles(.{
        .root = b.path("src"),
        .files = &.{
            "client.cpp",
            "server.cpp",
            "protocol.cpp",
        },
        .flags = &.{
            "-std=gnu++23",
        },
        .language = .cpp,
    });
    lib.installHeadersDirectory(asio.getEmittedIncludeTree(), "", .{
        .include_extensions = &.{ ".hpp", "ipp" },
    });
    lib.installHeadersDirectory(b.path("include"), "", .{
        .include_extensions = &.{ ".hpp", "ipp" },
    });

    const server = b.addExecutable(.{
        .name = "server",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });
    server.root_module.addIncludePath(b.path("include"));
    server.root_module.linkLibrary(lib);
    server.root_module.addCSourceFile(.{
        .file = b.path("src/main_server.cpp"),
        .flags = &.{
            "-std=gnu++23",
        },
        .language = .cpp,
    });

    const run_step = b.step("server", "Run the server");
    const run_cmd = b.addRunArtifact(server);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });
    benchmark.root_module.addIncludePath(b.path("include"));
    benchmark.root_module.linkLibrary(lib);
    benchmark.root_module.addCSourceFile(.{
        .file = b.path("src/bench_throughput.cpp"),
        .flags = &.{"-std=gnu++23"},
        .language = .cpp,
    });

    const benchmark_step = b.step("benchmark", "Run benchmark");
    const benchmark_cmd = b.addRunArtifact(benchmark);
    benchmark_step.dependOn(&benchmark_cmd.step);
    benchmark_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        benchmark_cmd.addArgs(args);
    }

    const exe = b.addExecutable(.{
        .name = "tests",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });
    exe.root_module.addCSourceFiles(.{
        .root = b.path("tests"),
        .files = &.{
            "test_compliance.cpp",
            "test_integration.cpp",
            "test_udp.cpp",
        },
        .flags = &.{"-std=gnu++23"},
        .language = .cpp,
    });
    exe.root_module.linkLibrary(lib);
    exe.root_module.linkLibrary(gtest_main);

    const test_step = b.step("test", "Run tests");
    const test_cmd = b.addRunArtifact(exe);
    test_step.dependOn(&test_cmd.step);
    test_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        test_cmd.addArgs(args);
    }
}
