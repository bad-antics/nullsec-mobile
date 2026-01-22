// NullSec Mobile - iOS Main App
// https://github.com/bad-antics | @AnonAntics
// discord.gg/killers

import SwiftUI

@main
struct NullSecApp: App {
    @StateObject private var appState = AppState()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .preferredColorScheme(.dark)
        }
    }
}

class AppState: ObservableObject {
    @Published var isPremium: Bool = false
    @Published var licenseKey: String = ""
    
    init() {
        loadPremiumStatus()
    }
    
    func loadPremiumStatus() {
        licenseKey = UserDefaults.standard.string(forKey: "license_key") ?? ""
        isPremium = validateLicense(key: licenseKey)
    }
    
    func validateLicense(key: String) -> Bool {
        // License validation - get key from discord.gg/killers
        return key.hasPrefix("NULLSEC-") && key.count == 32
    }
    
    func setLicenseKey(_ key: String) {
        licenseKey = key
        UserDefaults.standard.set(key, forKey: "license_key")
        isPremium = validateLicense(key: key)
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = 0
    @State private var showPremiumAlert = false
    
    var body: some View {
        TabView(selection: $selectedTab) {
            NetworkScannerView()
                .tabItem {
                    Image(systemName: "network")
                    Text("Scanner")
                }
                .tag(0)
            
            WifiAnalyzerView()
                .tabItem {
                    Image(systemName: "wifi")
                    Text("WiFi")
                }
                .tag(1)
            
            ToolsView()
                .tabItem {
                    Image(systemName: "wrench.and.screwdriver")
                    Text("Tools")
                }
                .tag(2)
            
            CryptoView()
                .tabItem {
                    Image(systemName: "lock.shield")
                    Text("Crypto")
                }
                .tag(3)
            
            SettingsView()
                .tabItem {
                    Image(systemName: "gear")
                    Text("Settings")
                }
                .tag(4)
        }
        .accentColor(Color("AccentRed"))
        .onAppear {
            if !appState.isPremium {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    showPremiumAlert = true
                }
            }
        }
        .alert("🔓 Unlock Premium", isPresented: $showPremiumAlert) {
            Button("Get Key") {
                openDiscord()
            }
            Button("Maybe Later", role: .cancel) {}
        } message: {
            Text("Get unlimited access to all features!\n\n• Unlimited network scanning\n• Full port range (1-65535)\n• Advanced hash cracking\n• Ad-free experience\n\nGet your key at discord.gg/killers")
        }
    }
    
    func openDiscord() {
        if let url = URL(string: "https://discord.gg/killers") {
            UIApplication.shared.open(url)
        }
    }
}

// MARK: - Network Scanner View
struct NetworkScannerView: View {
    @EnvironmentObject var appState: AppState
    @StateObject private var scanner = NetworkScanner()
    @State private var isScanning = false
    @State private var scanResults: [HostResult] = []
    
    var body: some View {
        NavigationView {
            VStack {
                // Header
                HStack {
                    VStack(alignment: .leading) {
                        Text("Local IP: \(scanner.localIP ?? "N/A")")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("Subnet: \(scanner.subnet ?? "N/A")")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    
                    Button(action: startScan) {
                        HStack {
                            if isScanning {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            } else {
                                Image(systemName: "magnifyingglass")
                            }
                            Text(isScanning ? "Scanning..." : "Scan")
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .background(Color("AccentRed"))
                        .foregroundColor(.white)
                        .cornerRadius(8)
                    }
                    .disabled(isScanning)
                }
                .padding()
                
                // Results
                if scanResults.isEmpty && !isScanning {
                    VStack(spacing: 16) {
                        Image(systemName: "network")
                            .font(.system(size: 64))
                            .foregroundColor(.secondary)
                        Text("Tap Scan to discover devices")
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(scanResults) { result in
                        HostResultRow(result: result)
                    }
                    .listStyle(PlainListStyle())
                }
                
                // Premium notice
                if !appState.isPremium {
                    HStack {
                        Image(systemName: "lock.fill")
                        Text("Free: 10 hosts | Premium: Unlimited")
                        Spacer()
                        Button("Upgrade") {
                            openDiscord()
                        }
                        .foregroundColor(Color("AccentRed"))
                    }
                    .font(.caption)
                    .padding()
                    .background(Color(.systemGray6))
                }
            }
            .navigationTitle("Network Scanner")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
    
    func startScan() {
        isScanning = true
        scanResults = []
        
        scanner.scan(premium: appState.isPremium) { results in
            scanResults = results
            isScanning = false
        }
    }
    
    func openDiscord() {
        if let url = URL(string: "https://discord.gg/killers") {
            UIApplication.shared.open(url)
        }
    }
}

struct HostResultRow: View {
    let result: HostResult
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(result.ip)
                    .font(.headline)
                Spacer()
                Text("\(result.responseTime)ms")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            if let hostname = result.hostname {
                Text(hostname)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            if !result.openPorts.isEmpty {
                HStack {
                    ForEach(result.openPorts.prefix(5), id: \.self) { port in
                        Text("\(port)")
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.green.opacity(0.2))
                            .foregroundColor(.green)
                            .cornerRadius(4)
                    }
                    if result.openPorts.count > 5 {
                        Text("+\(result.openPorts.count - 5)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Network Scanner Model
class NetworkScanner: ObservableObject {
    @Published var localIP: String?
    @Published var subnet: String?
    
    init() {
        localIP = getLocalIP()
        if let ip = localIP {
            let parts = ip.split(separator: ".")
            if parts.count == 4 {
                subnet = "\(parts[0]).\(parts[1]).\(parts[2]).0/24"
            }
        }
    }
    
    func getLocalIP() -> String? {
        var address: String?
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return nil
        }
        
        for ifptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ifptr.pointee
            let addrFamily = interface.ifa_addr.pointee.sa_family
            
            if addrFamily == UInt8(AF_INET) {
                let name = String(cString: interface.ifa_name)
                if name == "en0" {
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len),
                               &hostname, socklen_t(hostname.count), nil, socklen_t(0), NI_NUMERICHOST)
                    address = String(cString: hostname)
                }
            }
        }
        
        freeifaddrs(ifaddr)
        return address
    }
    
    func scan(premium: Bool, completion: @escaping ([HostResult]) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            var results: [HostResult] = []
            let maxHosts = premium ? 254 : 10
            
            guard let subnet = self.subnet?.replacingOccurrences(of: ".0/24", with: "") else {
                DispatchQueue.main.async {
                    completion([])
                }
                return
            }
            
            let group = DispatchGroup()
            let lock = NSLock()
            
            for i in 1...maxHosts {
                group.enter()
                let ip = "\(subnet).\(i)"
                
                DispatchQueue.global().async {
                    if let result = self.pingHost(ip: ip) {
                        lock.lock()
                        results.append(result)
                        lock.unlock()
                    }
                    group.leave()
                }
            }
            
            group.wait()
            
            DispatchQueue.main.async {
                completion(results.sorted { $0.ip < $1.ip })
            }
        }
    }
    
    func pingHost(ip: String) -> HostResult? {
        let start = Date()
        
        // Simple reachability check
        guard let url = URL(string: "http://\(ip)"),
              let host = url.host else {
            return nil
        }
        
        var request = URLRequest(url: url)
        request.timeoutInterval = 1.0
        request.httpMethod = "HEAD"
        
        let semaphore = DispatchSemaphore(value: 0)
        var isReachable = false
        
        let task = URLSession.shared.dataTask(with: request) { _, response, _ in
            if response != nil {
                isReachable = true
            }
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + 1.0)
        
        let elapsed = Int(Date().timeIntervalSince(start) * 1000)
        
        if isReachable {
            return HostResult(
                ip: ip,
                hostname: nil,
                mac: nil,
                openPorts: [80],
                responseTime: elapsed
            )
        }
        
        return nil
    }
}

struct HostResult: Identifiable {
    let id = UUID()
    let ip: String
    let hostname: String?
    let mac: String?
    let openPorts: [Int]
    let responseTime: Int
}

// MARK: - Placeholder Views
struct WifiAnalyzerView: View {
    var body: some View {
        NavigationView {
            VStack {
                Image(systemName: "wifi")
                    .font(.system(size: 64))
                    .foregroundColor(.secondary)
                Text("WiFi Analyzer")
                    .font(.headline)
                Text("Limited on iOS due to platform restrictions")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .navigationTitle("WiFi Analyzer")
        }
    }
}

struct ToolsView: View {
    var body: some View {
        NavigationView {
            List {
                NavigationLink(destination: PingView()) {
                    Label("Ping", systemImage: "antenna.radiowaves.left.and.right")
                }
                NavigationLink(destination: TracerouteView()) {
                    Label("Traceroute", systemImage: "point.topleft.down.curvedto.point.bottomright.up")
                }
                NavigationLink(destination: DNSLookupView()) {
                    Label("DNS Lookup", systemImage: "globe")
                }
                NavigationLink(destination: PortScanView()) {
                    Label("Port Scan", systemImage: "door.left.hand.open")
                }
                NavigationLink(destination: WhoisView()) {
                    Label("WHOIS", systemImage: "person.crop.circle.badge.questionmark")
                }
            }
            .navigationTitle("Tools")
        }
    }
}

struct CryptoView: View {
    @State private var inputText = ""
    @State private var outputText = ""
    @State private var selectedTool = 0
    
    let tools = ["Base64 Encode", "Base64 Decode", "MD5", "SHA-256", "URL Encode"]
    
    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                Picker("Tool", selection: $selectedTool) {
                    ForEach(0..<tools.count, id: \.self) { index in
                        Text(tools[index]).tag(index)
                    }
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(.horizontal)
                
                TextEditor(text: $inputText)
                    .frame(height: 120)
                    .padding(8)
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                    .padding(.horizontal)
                
                Button("Process") {
                    processInput()
                }
                .padding(.horizontal, 32)
                .padding(.vertical, 12)
                .background(Color("AccentRed"))
                .foregroundColor(.white)
                .cornerRadius(8)
                
                TextEditor(text: .constant(outputText))
                    .frame(height: 120)
                    .padding(8)
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                    .padding(.horizontal)
                
                Spacer()
            }
            .padding(.top)
            .navigationTitle("Crypto Tools")
        }
    }
    
    func processInput() {
        switch selectedTool {
        case 0: // Base64 Encode
            outputText = Data(inputText.utf8).base64EncodedString()
        case 1: // Base64 Decode
            if let data = Data(base64Encoded: inputText),
               let decoded = String(data: data, encoding: .utf8) {
                outputText = decoded
            } else {
                outputText = "Invalid Base64"
            }
        case 2: // MD5
            outputText = inputText.md5()
        case 3: // SHA-256
            outputText = inputText.sha256()
        case 4: // URL Encode
            outputText = inputText.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        default:
            outputText = inputText
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var licenseKey = ""
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("License")) {
                    HStack {
                        Text("Status")
                        Spacer()
                        Text(appState.isPremium ? "Premium ✓" : "Free")
                            .foregroundColor(appState.isPremium ? .green : .secondary)
                    }
                    
                    TextField("License Key", text: $licenseKey)
                    
                    Button("Activate") {
                        appState.setLicenseKey(licenseKey)
                    }
                    
                    Button("Get Key (Discord)") {
                        if let url = URL(string: "https://discord.gg/killers") {
                            UIApplication.shared.open(url)
                        }
                    }
                    .foregroundColor(Color("AccentRed"))
                }
                
                Section(header: Text("About")) {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text("1.0.0")
                            .foregroundColor(.secondary)
                    }
                    HStack {
                        Text("Developer")
                        Spacer()
                        Text("@AnonAntics")
                            .foregroundColor(.secondary)
                    }
                    
                    Link("GitHub", destination: URL(string: "https://github.com/bad-antics")!)
                    Link("Discord", destination: URL(string: "https://discord.gg/killers")!)
                    Link("GitHub", destination: URL(string: "https://github.com/bad-antics")!)
                }
            }
            .navigationTitle("Settings")
        }
    }
}

// Placeholder views for tools
struct PingView: View { var body: some View { Text("Ping Tool") } }
struct TracerouteView: View { var body: some View { Text("Traceroute Tool") } }
struct DNSLookupView: View { var body: some View { Text("DNS Lookup Tool") } }
struct PortScanView: View { var body: some View { Text("Port Scan Tool") } }
struct WhoisView: View { var body: some View { Text("WHOIS Tool") } }

// MARK: - Extensions
extension String {
    func md5() -> String {
        let data = Data(self.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    func sha256() -> String {
        let data = Data(self.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

import CommonCrypto
