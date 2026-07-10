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
  ],
  dependencies: [
    .package(url: "https://github.com/swiftlang/swift-testing.git", exact: "6.2.4")
  ],
  targets: [
    .target(name: "PasskeyCore"),
    .target(
      name: "PasskeyServer",
      dependencies: ["PasskeyCore"]
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
        .product(name: "Testing", package: "swift-testing"),
      ]
    ),
  ]
)
