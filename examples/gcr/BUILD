load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["main.go"],
    importpath = "k8s.io/kubernetes/pkg/credentialprovider/plugin/examples/gcr",
    visibility = ["//visibility:private"],
    deps = [
        "//pkg/credentialprovider/apis/credentials/v1alpha1:go_default_library",
        "//pkg/credentialprovider/plugin/framework:go_default_library",
        "//vendor/k8s.io/klog/v2:go_default_library",
    ],
)

go_binary(
    name = "gcr",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
