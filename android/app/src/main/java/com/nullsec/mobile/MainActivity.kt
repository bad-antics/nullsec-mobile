// NullSec Mobile - Main Activity
// https://github.com/bad-antics | @AnonAntics
// discord.gg/killers

package com.nullsec.mobile

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.nullsec.mobile.tools.*
import com.nullsec.mobile.ui.*

class MainActivity : AppCompatActivity() {

    companion object {
        const val PERMISSION_REQUEST_CODE = 1001
        val REQUIRED_PERMISSIONS = arrayOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.INTERNET
        )
    }

    private lateinit var bottomNav: BottomNavigationView
    private var isPremium = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        setupUI()
        checkPermissions()
        checkPremiumStatus()
    }

    private fun setupUI() {
        supportActionBar?.apply {
            title = "NullSec Mobile"
            subtitle = "Security Toolkit"
        }

        bottomNav = findViewById(R.id.bottom_navigation)
        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_scanner -> loadFragment(NetworkScannerFragment())
                R.id.nav_wifi -> loadFragment(WifiAnalyzerFragment())
                R.id.nav_tools -> loadFragment(ToolsFragment())
                R.id.nav_crypto -> loadFragment(CryptoToolsFragment())
                R.id.nav_settings -> loadFragment(SettingsFragment())
            }
            true
        }

        // Load default fragment
        loadFragment(NetworkScannerFragment())
    }

    private fun loadFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, fragment)
            .commit()
    }

    private fun checkPermissions() {
        val missingPermissions = REQUIRED_PERMISSIONS.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(
                this,
                missingPermissions.toTypedArray(),
                PERMISSION_REQUEST_CODE
            )
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        
        if (requestCode == PERMISSION_REQUEST_CODE) {
            val denied = grantResults.count { it != PackageManager.PERMISSION_GRANTED }
            if (denied > 0) {
                Toast.makeText(
                    this,
                    "Some features require permissions to work",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun checkPremiumStatus() {
        // Check for premium license key
        val prefs = getSharedPreferences("nullsec", MODE_PRIVATE)
        val licenseKey = prefs.getString("license_key", null)
        
        isPremium = licenseKey?.let { validateLicense(it) } ?: false
        
        if (!isPremium) {
            // Show premium prompt
            showPremiumDialog()
        }
    }

    private fun validateLicense(key: String): Boolean {
        // License validation - get key from discord.gg/killers
        // This is a placeholder for actual validation
        return key.startsWith("NULLSEC-") && key.length == 32
    }

    private fun showPremiumDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("🔓 Unlock Premium")
            .setMessage(
                "Get unlimited access to all features!\n\n" +
                "• Unlimited network scanning\n" +
                "• Full port range (1-65535)\n" +
                "• Advanced hash cracking\n" +
                "• Ad-free experience\n\n" +
                "Get your key at discord.gg/killers"
            )
            .setPositiveButton("Get Key") { _, _ ->
                openDiscord()
            }
            .setNegativeButton("Maybe Later", null)
            .show()
    }

    private fun openDiscord() {
        val intent = android.content.Intent(
            android.content.Intent.ACTION_VIEW,
            android.net.Uri.parse("https://discord.gg/killers")
        )
        startActivity(intent)
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_premium -> {
                showPremiumDialog()
                true
            }
            R.id.action_about -> {
                showAboutDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showAboutDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("NullSec Mobile")
            .setMessage(
                "Version: 1.0.0\n" +
                "Developer: @AnonAntics\n\n" +
                "Part of the NullSec Framework\n" +
                "https://github.com/bad-antics\n\n" +
                "Join us: discord.gg/killers"
            )
            .setPositiveButton("OK", null)
            .show()
    }
}
