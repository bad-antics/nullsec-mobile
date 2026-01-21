// NullSec Mobile - WiFi Analyzer Tool
// https://github.com/bad-antics | @AnonAntics
// discord.gg/killers

package com.nullsec.mobile.tools

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import androidx.core.content.ContextCompat

data class WifiNetwork(
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val frequency: Int,
    val channel: Int,
    val security: String,
    val capabilities: String,
    val isHidden: Boolean,
    val hasWps: Boolean
)

class WifiAnalyzer(private val context: Context) {

    companion object {
        // Channel frequency mappings
        private val CHANNEL_FREQUENCIES_2GHZ = mapOf(
            2412 to 1, 2417 to 2, 2422 to 3, 2427 to 4, 2432 to 5,
            2437 to 6, 2442 to 7, 2447 to 8, 2452 to 9, 2457 to 10,
            2462 to 11, 2467 to 12, 2472 to 13, 2484 to 14
        )
        
        private val CHANNEL_FREQUENCIES_5GHZ = mapOf(
            5180 to 36, 5200 to 40, 5220 to 44, 5240 to 48,
            5260 to 52, 5280 to 56, 5300 to 60, 5320 to 64,
            5500 to 100, 5520 to 104, 5540 to 108, 5560 to 112,
            5580 to 116, 5600 to 120, 5620 to 124, 5640 to 128,
            5660 to 132, 5680 to 136, 5700 to 140, 5720 to 144,
            5745 to 149, 5765 to 153, 5785 to 157, 5805 to 161, 5825 to 165
        )
    }

    private val wifiManager: WifiManager = 
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    
    private var scanListener: WifiScanListener? = null
    private var isPremium = false

    interface WifiScanListener {
        fun onScanComplete(networks: List<WifiNetwork>)
        fun onScanFailed(error: String)
    }

    private val wifiScanReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val success = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false)
            if (success) {
                processScanResults()
            } else {
                scanListener?.onScanFailed("Scan failed - try again")
            }
        }
    }

    fun startScan(listener: WifiScanListener) {
        this.scanListener = listener

        if (!hasPermissions()) {
            listener.onScanFailed("Location permission required for WiFi scanning")
            return
        }

        if (!wifiManager.isWifiEnabled) {
            listener.onScanFailed("WiFi is disabled")
            return
        }

        val intentFilter = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        context.registerReceiver(wifiScanReceiver, intentFilter)

        val success = wifiManager.startScan()
        if (!success) {
            listener.onScanFailed("Could not start WiFi scan")
        }
    }

    private fun hasPermissions(): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun processScanResults() {
        try {
            val results = wifiManager.scanResults
            val networks = results.map { scanResult ->
                WifiNetwork(
                    ssid = scanResult.SSID.ifEmpty { "<Hidden>" },
                    bssid = scanResult.BSSID,
                    rssi = scanResult.level,
                    frequency = scanResult.frequency,
                    channel = getChannel(scanResult.frequency),
                    security = getSecurity(scanResult.capabilities),
                    capabilities = scanResult.capabilities,
                    isHidden = scanResult.SSID.isEmpty(),
                    hasWps = scanResult.capabilities.contains("WPS")
                )
            }.sortedByDescending { it.rssi }

            scanListener?.onScanComplete(networks)
            context.unregisterReceiver(wifiScanReceiver)
        } catch (e: SecurityException) {
            scanListener?.onScanFailed("Permission denied")
        }
    }

    private fun getChannel(frequency: Int): Int {
        return CHANNEL_FREQUENCIES_2GHZ[frequency]
            ?: CHANNEL_FREQUENCIES_5GHZ[frequency]
            ?: ((frequency - 5000) / 5)
    }

    private fun getSecurity(capabilities: String): String {
        return when {
            capabilities.contains("WPA3") -> "WPA3"
            capabilities.contains("WPA2") && capabilities.contains("WPA") -> "WPA/WPA2"
            capabilities.contains("WPA2") -> "WPA2"
            capabilities.contains("WPA") -> "WPA"
            capabilities.contains("WEP") -> "WEP"
            else -> "Open"
        }
    }

    fun getSignalStrength(rssi: Int): String {
        return when {
            rssi >= -50 -> "Excellent"
            rssi >= -60 -> "Good"
            rssi >= -70 -> "Fair"
            rssi >= -80 -> "Weak"
            else -> "Very Weak"
        }
    }

    fun getSignalPercentage(rssi: Int): Int {
        return when {
            rssi >= -50 -> 100
            rssi <= -100 -> 0
            else -> 2 * (rssi + 100)
        }
    }

    fun getBand(frequency: Int): String {
        return when {
            frequency < 3000 -> "2.4 GHz"
            frequency < 6000 -> "5 GHz"
            else -> "6 GHz"
        }
    }

    fun getSecurityRating(security: String, hasWps: Boolean): String {
        val rating = when (security) {
            "WPA3" -> "Excellent"
            "WPA2" -> if (hasWps) "Good (WPS vulnerable)" else "Good"
            "WPA/WPA2" -> "Fair"
            "WPA" -> "Weak"
            "WEP" -> "Very Weak (Easily cracked)"
            "Open" -> "None (No encryption)"
            else -> "Unknown"
        }
        return rating
    }

    fun analyzeChannelCongestion(networks: List<WifiNetwork>): Map<Int, Int> {
        val channelCount = mutableMapOf<Int, Int>()
        networks.forEach { network ->
            val count = channelCount.getOrDefault(network.channel, 0)
            channelCount[network.channel] = count + 1
        }
        return channelCount.toSortedMap()
    }

    fun findBestChannel(networks: List<WifiNetwork>, band: String = "2.4 GHz"): Int {
        val relevantNetworks = networks.filter { 
            getBand(it.frequency) == band 
        }
        
        val channelCongestion = analyzeChannelCongestion(relevantNetworks)
        
        // For 2.4 GHz, prefer channels 1, 6, 11 (non-overlapping)
        val preferredChannels = if (band == "2.4 GHz") {
            listOf(1, 6, 11)
        } else {
            listOf(36, 40, 44, 48, 149, 153, 157, 161)
        }
        
        return preferredChannels.minByOrNull { channel ->
            channelCongestion.getOrDefault(channel, 0)
        } ?: preferredChannels.first()
    }

    fun getConnectedNetwork(): WifiNetwork? {
        val wifiInfo = wifiManager.connectionInfo
        if (wifiInfo.networkId == -1) return null
        
        return WifiNetwork(
            ssid = wifiInfo.ssid.removeSurrounding("\""),
            bssid = wifiInfo.bssid ?: "",
            rssi = wifiInfo.rssi,
            frequency = wifiInfo.frequency,
            channel = getChannel(wifiInfo.frequency),
            security = "Connected",
            capabilities = "",
            isHidden = false,
            hasWps = false
        )
    }

    fun exportToJson(networks: List<WifiNetwork>): String {
        val sb = StringBuilder()
        sb.append("{\n  \"wifi_networks\": [\n")
        
        networks.forEachIndexed { index, network ->
            sb.append("    {\n")
            sb.append("      \"ssid\": \"${network.ssid}\",\n")
            sb.append("      \"bssid\": \"${network.bssid}\",\n")
            sb.append("      \"rssi\": ${network.rssi},\n")
            sb.append("      \"channel\": ${network.channel},\n")
            sb.append("      \"frequency\": ${network.frequency},\n")
            sb.append("      \"security\": \"${network.security}\",\n")
            sb.append("      \"hidden\": ${network.isHidden},\n")
            sb.append("      \"wps\": ${network.hasWps}\n")
            sb.append("    }")
            if (index < networks.size - 1) sb.append(",")
            sb.append("\n")
        }
        
        sb.append("  ],\n")
        sb.append("  \"generated_by\": \"NullSec Mobile\",\n")
        sb.append("  \"discord\": \"discord.gg/killers\"\n")
        sb.append("}")
        
        return sb.toString()
    }

    fun setPremium(premium: Boolean) {
        isPremium = premium
    }
}
