import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

public struct PasskeyHTTPServer: Sendable {
  private let api: PasskeyAPI

  public init(api: PasskeyAPI) {
    self.api = api
  }

  public func run(host: String, port: Int) throws {
    let api = api
    let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
    defer {
      try? group.syncShutdownGracefully()
    }

    let channel = try ServerBootstrap(group: group)
      .serverChannelOption(ChannelOptions.backlog, value: 256)
      .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .childChannelInitializer { channel in
        channel.pipeline.configureHTTPServerPipeline().flatMap {
          channel.pipeline.addHandler(PasskeyHTTPHandler(api: api))
        }
      }
      .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
      .bind(host: host, port: port)
      .wait()

    print("Passkey server listening on http://\(host):\(port)")
    try channel.closeFuture.wait()
  }
}

/// NIO invokes this handler only on its channel's event loop. Mutable request
/// state therefore never crosses executors even though the pipeline requires a
/// Sendable handler value.
private final class PasskeyHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = HTTPServerRequestPart
  typealias OutboundOut = HTTPServerResponsePart

  private let api: PasskeyAPI
  private var requestHead: HTTPRequestHead?
  private var requestBody: ByteBuffer?
  private var isProcessing = false

  init(api: PasskeyAPI) {
    self.api = api
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    guard !isProcessing else { return }

    switch unwrapInboundIn(data) {
    case .head(let head):
      guard requestHead == nil else {
        writeAndClose(
          HTTPResponseData(status: 400, body: Data("Invalid request".utf8)),
          context: context
        )
        return
      }
      if let contentLength = head.headers.first(name: "content-length").flatMap(Int.init),
        contentLength > PasskeyAPI.maximumBodyBytes
      {
        writeAndClose(
          HTTPResponseData(status: 413, body: Data("Request body too large".utf8)),
          context: context
        )
        return
      }
      requestHead = head
      requestBody = context.channel.allocator.buffer(capacity: 0)

    case .body(var body):
      guard var collected = requestBody else { return }
      if collected.readableBytes + body.readableBytes > PasskeyAPI.maximumBodyBytes {
        writeAndClose(
          HTTPResponseData(status: 413, body: Data("Request body too large".utf8)),
          context: context
        )
        return
      }
      collected.writeBuffer(&body)
      requestBody = collected

    case .end:
      guard let head = requestHead, let body = requestBody else { return }
      isProcessing = true
      let bodyData = Data(body.readableBytesView)
      var headers: [String: String] = [:]
      for header in head.headers {
        headers[header.name.lowercased()] = header.value
      }
      let request = HTTPRequestData(
        method: head.method.rawValue,
        path: head.uri,
        headers: headers,
        body: bodyData,
        requestID: UUID().uuidString.lowercased()
      )

      let promise = context.eventLoop.makePromise(of: HTTPResponseData.self)
      let api = api
      promise.completeWithTask {
        await api.handle(request)
      }
      let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
      promise.futureResult.whenSuccess { response in
        self.writeAndClose(response, context: loopBoundContext.value)
      }
    }
  }

  func errorCaught(context: ChannelHandlerContext, error: Error) {
    context.close(promise: nil)
  }

  private func writeAndClose(
    _ response: HTTPResponseData,
    context: ChannelHandlerContext
  ) {
    isProcessing = true
    var headers = HTTPHeaders()
    for (name, value) in response.headers {
      headers.add(name: name, value: value)
    }
    headers.replaceOrAdd(name: "content-length", value: String(response.body.count))
    headers.replaceOrAdd(name: "connection", value: "close")

    let responseHead = HTTPResponseHead(
      version: .http1_1,
      status: HTTPResponseStatus(statusCode: response.status),
      headers: headers
    )
    context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
    if !response.body.isEmpty {
      var buffer = context.channel.allocator.buffer(capacity: response.body.count)
      buffer.writeBytes(response.body)
      context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
    }
    context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    context.close(promise: nil)
  }
}
