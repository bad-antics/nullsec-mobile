// NullSec Mobile - Network Scanner Tool
// https://github.com/bad-antics | @AnonAntics
// discord.gg/killers

package com.nullsec.mobile.tools

import android.content.Context
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

data class ScanResult(
    val ip: String,
    val hostname: String?,
    val mac: String?,
    val openPorts: List<Int>,
    val services: Map<Int, String>,
    val responseTime: Long,
    val isAlive: Boolean
)

class NetworkScanner(private val context: Context) {
    
    companion object {
        // Common ports for quick scan
        val COMMON_PORTS = listOf(
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
            6379, 8080, 8443, 27017
        )
        
        // Service identification
        val PORT_SERVICES = mapOf(
            21 to "FTP",
            22 to "SSH",
            23 to "Telnet",
            25 to "SMTP",
            53 to "DNS",
            80 to "HTTP",
            110 to "POP3",
            143 to "IMAP",
            443 to "HTTPS",
            445 to "SMB",
            993 to "IMAPS",
            995 to "POP3S",
            1433 to "MSSQL",
            1521 to "Oracle",
            3306 to "MySQL",
            3389 to "RDP",
            5432 to "PostgreSQL",
            5900 to "VNC",
            6379 to "Redis",
            8080 to "HTTP-Proxy",
            8443 to "HTTPS-Alt",
            27017 to "MongoDB"
        )

        const val DEFAULT_TIMEOUT = 1000
        const val MAX_THREADS = 100
    }

    private val results = ConcurrentHashMap<String, ScanResult>()
    private val scannedCount = AtomicInteger(0)
    private var isPremium = false

    interface ScanListener {
        fun onHostFound(result: ScanResult)
        fun onProgress(current: Int, total: Int)
        fun onComplete(results: List<ScanResult>)
        fun onError(error: String)
    }

    fun getLocalIP(): String? {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = wifiManager.connectionInfo
        val ip = wifiInfo.ipAddress
        
        return if (ip != 0) {
            String.format(
                "%d.%d.%d.%d",
                ip and 0xff,
                ip shr 8 and 0xff,
                ip shr 16 and 0xff,
                ip shr 24 and 0xff
            )
        } else null
    }

    fun getSubnet(): String? {
        val localIP = getLocalIP() ?: return null
        val parts = localIP.split(".")
        return "${parts[0]}.${parts[1]}.${parts[2]}"
    }

    suspend fun scanNetwork(
        listener: ScanListener,
        timeout: Int = DEFAULT_TIMEOUT,
        scanPorts: Boolean = true
    ) = withContext(Dispatchers.IO) {
        val subnet = getSubnet()
        if (subnet == null) {
            listener.onError("Could not determine network subnet")
            return@withContext
        }

        results.clear()
        scannedCount.set(0)
        
        val totalHosts = if (isPremium) 254 else 10 // Free limited to 10 hosts
        val jobs = mutableListOf<Job>()

        for (i in 1..totalHosts) {
            val ip = "$subnet.$i"
            jobs.add(launch {
                val result = scanHost(ip, timeout, scanPorts)
                if (result.isAlive) {
                    results[ip] = result
                    withContext(Dispatchers.Main) {
                        listener.onHostFound(result)
                    }
                }
                val current = scannedCount.incrementAndGet()
                withContext(Dispatchers.Main) {
                    listener.onProgress(current, totalHosts)
                }
            })

            // Limit concurrent connections
            if (jobs.size >= MAX_THREADS) {
                jobs.first().join()
                jobs.removeAt(0)
            }
        }

        jobs.forEach { it.join() }

        withContext(Dispatchers.Main) {
            listener.onComplete(results.values.toList().sortedBy { 
                it.ip.split(".").last().toInt() 
            })
        }

        if (!isPremium && totalHosts < 254) {
            withContext(Dispatchers.Main) {
                listener.onError("Free version limited to $totalHosts hosts. Get premium at discord.gg/killers")
            }
        }
    }

    suspend fun scanHost(
        ip: String,
        timeout: Int = DEFAULT_TIMEOUT,
        scanPorts: Boolean = true
    ): ScanResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        
        // Ping check
        val isAlive = try {
            InetAddress.getByName(ip).isReachable(timeout)
        } catch (e: Exception) {
            false
        }

        if (!isAlive) {
            return@withContext ScanResult(
                ip = ip,
                hostname = null,
                mac = null,
                openPorts = emptyList(),
                services = emptyMap(),
                responseTime = 0,
                isAlive = false
            )
        }

        val responseTime = System.currentTimeMillis() - startTime

        // Get hostname
        val hostname = try {
            InetAddress.getByName(ip).hostName.takeIf { it != ip }
        } catch (e: Exception) {
            null
        }

        // Port scan
        val openPorts = mutableListOf<Int>()
        val services = mutableMapOf<Int, String>()

        if (scanPorts) {
            val portsToScan = if (isPremium) (1..65535).toList() else COMMON_PORTS
            
            portsToScan.forEach { port ->
                if (isPortOpen(ip, port, timeout / 2)) {
                    openPorts.add(port)
                    PORT_SERVICES[port]?.let { services[port] = it }
                }
            }
        }

        ScanResult(
            ip = ip,
            hostname = hostname,
            mac = getMacFromArp(ip),
            openPorts = openPorts,
            services = services,
            responseTime = responseTime,
            isAlive = true
        )
    }

    private fun isPortOpen(ip: String, port: Int, timeout: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeout)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun getMacFromArp(ip: String): String? {
        return try {
            Runtime.getRuntime().exec("cat /proc/net/arp").inputStream
                .bufferedReader()
                .readLines()
                .find { it.contains(ip) }
                ?.split("\\s+".toRegex())
                ?.getOrNull(3)
                ?.uppercase()
        } catch (e: Exception) {
            null
        }
    }

    suspend fun scanPorts(
        ip: String,
        startPort: Int,
        endPort: Int,
        timeout: Int = DEFAULT_TIMEOUT,
        listener: ScanListener
    ) = withContext(Dispatchers.IO) {
        val maxPort = if (isPremium) endPort else minOf(endPort, 1024)
        val openPorts = mutableListOf<Int>()
        val services = mutableMapOf<Int, String>()
        var scanned = 0
        val total = maxPort - startPort + 1

        for (port in startPort..maxPort) {
            if (isPortOpen(ip, port, timeout)) {
                openPorts.add(port)
                PORT_SERVICES[port]?.let { services[port] = it }
            }
            scanned++
            withContext(Dispatchers.Main) {
                listener.onProgress(scanned, total)
            }
        }

        val result = ScanResult(
            ip = ip,
            hostname = null,
            mac = null,
            openPorts = openPorts,
            services = services,
            responseTime = 0,
            isAlive = true
        )

        withContext(Dispatchers.Main) {
            listener.onComplete(listOf(result))
        }

        if (!isPremium && endPort > 1024) {
            withContext(Dispatchers.Main) {
                listener.onError("Free version limited to ports 1-1024. Get premium at discord.gg/killers")
            }
        }
    }

    fun setPremium(premium: Boolean) {
        isPremium = premium
    }

    fun exportToJson(results: List<ScanResult>): String {
        val sb = StringBuilder()
        sb.append("{\n  \"scan_results\": [\n")
        
        results.forEachIndexed { index, result ->
            sb.append("    {\n")
            sb.append("      \"ip\": \"${result.ip}\",\n")
            sb.append("      \"hostname\": ${result.hostname?.let { "\"$it\"" } ?: "null"},\n")
            sb.append("      \"mac\": ${result.mac?.let { "\"$it\"" } ?: "null"},\n")
            sb.append("      \"open_ports\": [${result.openPorts.joinToString(", ")}],\n")
            sb.append("      \"response_time\": ${result.responseTime}\n")
            sb.append("    }")
            if (index < results.size - 1) sb.append(",")
            sb.append("\n")
        }
        
        sb.append("  ],\n")
        sb.append("  \"generated_by\": \"NullSec Mobile\",\n")
        sb.append("  \"discord\": \"discord.gg/killers\"\n")
        sb.append("}")
        
        return sb.toString()
    }
}
