// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "LearnPasskey",
  platforms: [
    .macOS(.v15),
    .iOS(.v17),
  ],
  products: [
    .library(name: "PasskeyCore", targets: ["PasskeyCore"]),
    .library(name: "PasskeyServer", targets: ["PasskeyServer"]),
    .library(name: "PasskeyHTTP", targets: ["PasskeyHTTP"]),
    .executable(name: "PasskeyServerCLI", targets: ["PasskeyServerCLI"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
    .package(url: "https://github.com/apple/swift-nio.git", exact: "2.101.2"),
    .package(url: "https://github.com/swiftlang/swift-testing.git", exact: "6.2.4"),
  ],
  targets: [
    .target(name: "PasskeyCore"),
    .target(
      name: "PasskeyServer",
      dependencies: [
        "PasskeyCore",
        .product(name: "Crypto", package: "swift-crypto"),
      ]
    ),
    .target(
      name: "PasskeyHTTP",
      dependencies: [
        "PasskeyCore",
        "PasskeyServer",
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
      ]
    ),
    .executableTarget(
      name: "PasskeyServerCLI",
      dependencies: [
        "PasskeyHTTP",
        "PasskeyServer",
      ]
    ),
    .testTarget(
      name: "PasskeyCoreTests",
      dependencies: [
        "PasskeyCore",
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
    .testTarget(
      name: "PasskeyServerTests",
      dependencies: [
        "PasskeyCore",
        "PasskeyServer",
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
    .testTarget(
      name: "PasskeyHTTPTests",
      dependencies: [
        "PasskeyCore",
        "PasskeyHTTP",
        "PasskeyServer",
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
  ]
)
