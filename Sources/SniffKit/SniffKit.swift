import syslibpcap
import Logging
import sysinet

fileprivate func makeDefaultLogger() -> Logger {
	var newLogger = Logger(label:"interface-sniffer")
	#if DEBUG
	newLogger.logLevel = .debug
	#else
	newLogger.logLevel = .info
	#endif
	return newLogger
}

fileprivate func packetHandler(user:UnsafeMutablePointer<u_char>!, header:UnsafePointer<pcap_pkthdr>!, packet:UnsafePointer<u_char>!) {
    print("got some packet wow")
    var headersPackage = header_pkg_t()
    parseHeaders(header, packet, &headersPackage)    
}

public protocol PacketHandler {

}

public class InterfaceSniffer {
	struct SniffedUDP:Hashable {
		let sourceMAC:String
		let destMAC:String
		let sourceIP:String
		let destIP:String
		let sport:UInt16
		let dport:UInt16
	}
	enum Error:Swift.Error {
		case pcapOpenError
		case pcapSetupFilterError
		case pcapLoopError
	}
	
	public var logger:Logger
	
	private var device:String
	private var errorBuffer:UnsafeMutableBufferPointer<CChar>
	private let handle:OpaquePointer
	
	private var loopTask:Task<Void, Swift.Error>? = nil
	
	init(deviceName:String, logger:Logger = makeDefaultLogger()) throws {
		self.logger = logger
		self.device = deviceName
		let errorBuff = UnsafeMutableBufferPointer<CChar>.allocate(capacity:Int(PCAP_ERRBUF_SIZE))
		guard let capHandle = pcap_open_live(deviceName, BUFSIZ, 1, 0, errorBuff.baseAddress) else {
			logger.error("unable to open pcap.", metadata:["interface-name":"\(deviceName)"])
			throw Error.pcapOpenError
		}
		self.handle = capHandle
		self.errorBuffer = errorBuff
		var makeFilter = bpf_program()
		defer {
			pcap_freecode(&makeFilter)
		}
		guard pcap_compile(capHandle, &makeFilter, "udp", 1, PCAP_NETMASK_UNKNOWN) == 0 && pcap_setfilter(capHandle, &makeFilter) == 0 && pcap_set_timeout(capHandle, 1000) == 0 else {
			logger.error("unable to enable pcap filter.")
			throw Error.pcapSetupFilterError
		}
		
	}
	
	func run() {
		self.loopTask = Task.detached { [selfPtr = Unmanaged.passUnretained(self)] in
			try await withUnsafeThrowingContinuation { (myContinuation:UnsafeContinuation<Void, Swift.Error>) in
				guard pcap_loop(self.handle, -1, packetHandler, selfPtr.toOpaque()) == 0 else {
					myContinuation.resume(throwing:Error.pcapLoopError)
					return
				}
				myContinuation.resume()
			}
			
		}
	}
	
	
	deinit {
		pcap_close(self.handle)
	}
}

@main
public struct SniffKit {
	public static func main() {
	
	}
}
