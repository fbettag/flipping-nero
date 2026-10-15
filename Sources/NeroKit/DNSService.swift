import Foundation
import Network
import dnssd

/// DNS record queries and Bonjour browsing over dnssd (the only DNS API iOS exposes
/// for arbitrary record types). A/AAAA go through getaddrinfo.
public enum DNSResolver {
    public static func addresses(for host: String) -> [IPv4Address] {
        var hints = addrinfo(ai_flags: 0, ai_family: Int32(AF_INET), ai_socktype: Int32(SOCK_STREAM),
                             ai_protocol: Int32(IPPROTO_TCP), ai_addrlen: 0, ai_canonname: nil,
                             ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return [] }
        defer { freeaddrinfo(result) }
        var addresses: [IPv4Address] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let current = cursor {
            if let addr = current.pointee.ai_addr, addr.pointee.sa_family == UInt8(AF_INET),
               Int(addr.pointee.sa_len) >= 8 {
                let bytes = Data(bytes: addr, count: Int(addr.pointee.sa_len))
                let value = UInt32(bytes[bytes.startIndex + 4]) << 24 | UInt32(bytes[bytes.startIndex + 5]) << 16
                    | UInt32(bytes[bytes.startIndex + 6]) << 8 | UInt32(bytes[bytes.startIndex + 7])
                addresses.append(IPv4Address(value))
            }
            cursor = current.pointee.ai_next
        }
        return addresses
    }

    public static func ptr(for address: IPv4Address, timeout: Duration = .seconds(2)) async -> String? {
        let bytes = withUnsafeBytes(of: address.value.bigEndian) { Data($0) }
        let name = bytes.map { String($0) }.joined(separator: ".") + ".in-addr.arpa"
        guard let records = try? await query(name: name, rrtype: DNSRecord.ptr, timeout: timeout),
              let record = records.first else { return nil }
        return DNSRecord.parseName(from: record.data, offset: 0).string
    }

    /// One record query. Callbacks arrive on the dnssd dispatch queue; the query ends
    /// with everything collected by the deadline.
    public static func query(name: String, rrtype: UInt16, timeout: Duration) async throws -> [DNSRecord] {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[DNSRecord], Error>) in
            let box = QueryBox(cont: cont)
            var service: DNSServiceRef?
            let context = Unmanaged.passRetained(box).toOpaque()
            box.setOpaque(context)
            let error = name.withCString { cname in
                DNSServiceQueryRecord(&service, 0, 0, cname, rrtype, UInt16(kDNSServiceClass_IN), { _, flags, _,
                    errorCode, fullname, rrtype, _, rdlength, rdata, _, context in
                    let box = Unmanaged<QueryBox>.fromOpaque(context!).takeUnretainedValue()
                    guard errorCode == kDNSServiceErr_NoError else {
                        box.finish(.failure(DNSError(code: Int(errorCode))))
                        return
                    }
                    if let fullname, let rdata, rdlength > 0 {
                        box.append(DNSRecord(name: String(cString: fullname), rrtype: rrtype,
                                             data: Data(bytes: rdata, count: Int(rdlength))))
                    }
                    if flags & kDNSServiceFlagsMoreComing == 0 { box.finish(.success(box.snapshot())) }
                }, context)
            }
            guard error == kDNSServiceErr_NoError, let service else {
                box.finish(.failure(DNSError(code: Int(error))))
                return
            }
            box.setService(service)
            DNSServiceSetDispatchQueue(service, Self.queue)
            box.scheduleTimeout(after: timeout, queue: Self.queue)
        }
    }

    public struct DNSError: Error, CustomStringConvertible {
        public let code: Int
        public var description: String { "dnssd error \(code)" }
    }

    final class QueryBox: @unchecked Sendable {
        let lock = NSLock()
        private var records: [DNSRecord] = []
        private var finished = false
        private var service: DNSServiceRef?
        private var opaque: UnsafeMutableRawPointer?
        private let cont: CheckedContinuation<[DNSRecord], Error>

        init(cont: CheckedContinuation<[DNSRecord], Error>) { self.cont = cont }

        func append(_ record: DNSRecord) {
            lock.lock()
            records.append(record)
            lock.unlock()
        }

        func snapshot() -> [DNSRecord] {
            lock.lock()
            defer { lock.unlock() }
            return records
        }

        func setService(_ service: DNSServiceRef) {
            lock.lock()
            self.service = service
            lock.unlock()
        }

        func setOpaque(_ pointer: UnsafeMutableRawPointer) {
            lock.lock()
            opaque = pointer
            lock.unlock()
        }

        /// Resumes exactly once, deallocates the dnssd service and drops the retained self.
        func finish(_ result: Result<[DNSRecord], Error>) {
            lock.lock()
            guard !finished else { lock.unlock(); return }
            finished = true
            let service = self.service
            let opaque = self.opaque
            self.service = nil
            self.opaque = nil
            lock.unlock()
            if let service { DNSServiceRefDeallocate(service) }
            cont.resume(with: result)
            if let opaque { Unmanaged<QueryBox>.fromOpaque(opaque).release() }
        }

        func scheduleTimeout(after timeout: Duration, queue: DispatchQueue) {
            let seconds = Double(timeout.components.seconds) + Double(timeout.components.attoseconds) / 1e18
            queue.asyncAfter(deadline: DispatchTime.now() +   max(0.05, seconds)) { [weak self] in
                self?.finish(.failure(ProbeError.timeout("dns query")))
            }
        }
    }

    static let queue = DispatchQueue(label: "nero.dns", qos: .utility)
}

/// Browses the declared service types (NWBrowser) and resolves each instance once
/// (DNSServiceResolve) for port and TXT. Wildcard browsing needs a multicast
/// entitlement the app does not ship; declared types need none.
enum BonjourResolver {
    public static func browseAndResolve(types: [String], timeout: Duration) async -> [BonjourService] {
        await withTaskGroup(of: [BonjourService].self) { group in
            for type in types {
                group.addTask { await browseOne(type: type, timeout: timeout) }
            }
            var all: [BonjourService] = []
            while let partial = await group.next() { all += partial }
            return all
        }
    }

    static func browseOne(type: String, timeout: Duration) async -> [BonjourService] {
        let instances = await browse(type: type, timeout: min(timeout, .seconds(2)))
        guard !instances.isEmpty else { return [] }
        let resolved = await Parallel.map(Array(instances.prefix(20)), limit: 6) { instance in
            await resolve(type: type, instance: instance, timeout: timeout)
        }
        return resolved.compactMap { $0 }
    }

    /// Instance names visible for one service type.
    static func browse(type: String, timeout: Duration) async -> [String] {
        await withCheckedContinuation { (cont: CheckedContinuation<[String], Never>) in
            let box = BrowseBox(cont: cont)
            let browser = NWBrowser(for: .bonjourWithTXTRecord(type: type, domain: nil), using: NWParameters())
            box.browser = browser
            browser.browseResultsChangedHandler = { results, _ in
                box.replace(results.compactMap { result in
                    if case .service(let name, _, _, _) = result.endpoint { return name }
                    return nil
                })
            }
            browser.stateUpdateHandler = { state in
                if case .failed(let error) = state { box.finish(failed: "\(error)") }
            }
            browser.start(queue: DNSResolver.queue)
            DNSResolver.queue.asyncAfter(deadline: DispatchTime.now() +   max(0.1, timeValue(timeout))) { box.finish(failed: nil) }
        }
    }

    /// One DNSServiceResolve for port and TXT of an instance. The first callback answers;
    /// a single resolve delivers the complete record, possibly flagged MoreComing.
    static func resolve(type: String, instance: String, timeout: Duration) async -> BonjourService? {
        await withCheckedContinuation { (cont: CheckedContinuation<BonjourService?, Never>) in
            let box = ResolveBox(cont: cont, instance: instance, type: type)
            var service: DNSServiceRef?
            let context = Unmanaged.passRetained(box).toOpaque()
            box.setOpaque(context)
            let error = DNSServiceResolve(&service, 0, 0, instance, type, "local.", { _, _, _, errorCode,
                fullname, host, port, txtLen, txtRecord, context in
                let box = Unmanaged<ResolveBox>.fromOpaque(context!).takeUnretainedValue()
                guard errorCode == kDNSServiceErr_NoError else { box.finish(nil); return }
                box.store(fullname: fullname.map { String(cString: $0) },
                          port: UInt16(bigEndian: port),
                          txt: txtRecord.map { BonjourResolver.parseTXT($0, length: Int(txtLen)) } ?? [])
                box.finish(box.snapshot())
            }, context)
            guard error == kDNSServiceErr_NoError, let service else {
                box.finish(nil)
                return
            }
            box.setService(service)
            DNSServiceSetDispatchQueue(service, DNSResolver.queue)
            DNSResolver.queue.asyncAfter(deadline: DispatchTime.now() +   max(0.1, timeValue(timeout))) { box.finish(box.snapshot()) }
        }
    }

    static func parseTXT(_ record: UnsafePointer<UInt8>, length: Int) -> [String] {
        var lines: [String] = []
        let count = TXTRecordGetCount(UInt16(length), record)
        for index in 0..<count {
            var key = [CChar](repeating: 0, count: 256)
            var valueLength: UInt8 = 0
            var value: UnsafeRawPointer?
            let result = withUnsafeMutablePointer(to: &key) { keyPointer in
                withUnsafeMutablePointer(to: &valueLength) { lengthPointer in
                    withUnsafeMutablePointer(to: &value) { valuePointer in
                        TXTRecordGetItemAtIndex(UInt16(index), record, UInt16(length), 256,
                                                keyPointer, lengthPointer, valuePointer)
                    }
                }
            }
            guard result == kDNSServiceErr_NoError, let keyString = String(validatingUTF8: key) else { continue }
            if let value, valueLength > 0 {
                let text = String(decoding: Data(bytes: value, count: Int(valueLength)), as: UTF8.self)
                lines.append("\(keyString)=\(TextSanitizer.clean(text, maxLength: 120))")
            } else {
                lines.append(keyString)
            }
        }
        return lines
    }

    static func timeValue(_ duration: Duration) -> TimeInterval {
        Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
    }
}

private final class BrowseBox: @unchecked Sendable {
    let lock = NSLock()
    private var names: [String] = []
    private var finished = false
    var browser: NWBrowser?
    private let cont: CheckedContinuation<[String], Never>
    init(cont: CheckedContinuation<[String], Never>) { self.cont = cont }

    func replace(_ names: [String]) {
        lock.lock()
        self.names = names
        lock.unlock()
    }

    func finish(failed: String?) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let names = self.names
        let browser = self.browser
        lock.unlock()
        browser?.cancel()
        cont.resume(returning: failed == nil ? names : [])
    }
}

private final class ResolveBox: @unchecked Sendable {
    let lock = NSLock()
    private var port: UInt16 = 0
    private var txt: [String] = []
    private var finished = false
    private var service: DNSServiceRef?
    private var opaque: UnsafeMutableRawPointer?
    private let instance: String
    private let type: String
    private let cont: CheckedContinuation<BonjourService?, Never>
    init(cont: CheckedContinuation<BonjourService?, Never>, instance: String, type: String) {
        self.cont = cont
        self.instance = instance
        self.type = type
    }

    func store(fullname: String?, port: UInt16, txt: [String]) {
        lock.lock()
        if port != 0 { self.port = port }
        if !txt.isEmpty { self.txt = txt }
        lock.unlock()
    }

    func snapshot() -> BonjourService? {
        lock.lock()
        defer { lock.unlock() }
        guard port != 0 else { return nil }
        return BonjourService(name: instance, type: type, domain: "local", port: port, txt: txt)
    }

    func setService(_ service: DNSServiceRef) {
        lock.lock()
        self.service = service
        lock.unlock()
    }

    func setOpaque(_ pointer: UnsafeMutableRawPointer) {
        lock.lock()
        opaque = pointer
        lock.unlock()
    }

    func finish(_ service: BonjourService?) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let dnssdService = self.service
        let opaque = self.opaque
        self.service = nil
        self.opaque = nil
        lock.unlock()
        if let dnssdService { DNSServiceRefDeallocate(dnssdService) }
        cont.resume(returning: service)
        if let opaque { Unmanaged<ResolveBox>.fromOpaque(opaque).release() }
    }
}
