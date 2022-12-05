import syslibpcap
import Logging

fileprivate func makeDefaultLogger() -> Logger {
	var newLogger = Logger(label:"interface-sniffer")
	#if DEBUG
	newLogger.logLevel = .debug
	#else
	newLogger.logLevel = .info
	#endif
	return newLogger
}

public class InterfaceSniffer {
	
	enum Error:Swift.Error {
		case pcapOpenError
		case pcapSetupFilterError
	}
	
	public var logger:Logger
	
	private var device:String
	private var errorBuffer:UnsafeMutableBufferPointer<CChar>
	private let handle:OpaquePointer
	
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
		guard pcap_compile(capHandle, &makeFilter, "udp", 1, PCAP_NETMASK_UNKNOWN) == 0 && pcap_setfilter(capHandle, &makeFilter) == 0 else {
			logger.error("unable to enable pcap filter.")
			throw Error.pcapSetupFilterError
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
