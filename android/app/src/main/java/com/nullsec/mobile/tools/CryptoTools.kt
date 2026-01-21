// NullSec Mobile - Hash & Crypto Tools
// https://github.com/bad-antics | @AnonAntics
// discord.gg/killers

package com.nullsec.mobile.tools

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class HashTools {

    companion object {
        val SUPPORTED_HASHES = listOf("MD5", "SHA-1", "SHA-256", "SHA-512")
    }

    fun md5(input: String): String {
        return hash(input, "MD5")
    }

    fun sha1(input: String): String {
        return hash(input, "SHA-1")
    }

    fun sha256(input: String): String {
        return hash(input, "SHA-256")
    }

    fun sha512(input: String): String {
        return hash(input, "SHA-512")
    }

    fun hash(input: String, algorithm: String): String {
        val digest = MessageDigest.getInstance(algorithm)
        val hashBytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hashBytes.joinToString("") { "%02x".format(it) }
    }

    fun hashFile(bytes: ByteArray, algorithm: String): String {
        val digest = MessageDigest.getInstance(algorithm)
        val hashBytes = digest.digest(bytes)
        return hashBytes.joinToString("") { "%02x".format(it) }
    }

    fun identifyHash(hash: String): List<String> {
        val possibleTypes = mutableListOf<String>()
        val cleanHash = hash.trim().lowercase()
        
        when (cleanHash.length) {
            32 -> possibleTypes.add("MD5")
            40 -> possibleTypes.add("SHA-1")
            64 -> {
                possibleTypes.add("SHA-256")
                if (cleanHash.startsWith("\$5\$")) {
                    possibleTypes.add("SHA-256 Crypt")
                }
            }
            128 -> possibleTypes.add("SHA-512")
            60 -> if (cleanHash.startsWith("\$2")) possibleTypes.add("bcrypt")
            34 -> if (cleanHash.matches(Regex("^[a-f0-9]{32}$"))) possibleTypes.add("NTLM")
        }
        
        // Check for common prefixes
        if (cleanHash.startsWith("\$1\$")) possibleTypes.add("MD5 Crypt")
        if (cleanHash.startsWith("\$6\$")) possibleTypes.add("SHA-512 Crypt")
        if (cleanHash.startsWith("\$apr1\$")) possibleTypes.add("Apache MD5")
        
        if (possibleTypes.isEmpty()) {
            possibleTypes.add("Unknown")
        }
        
        return possibleTypes
    }

    fun generateNTLM(password: String): String {
        val unicode = password.toByteArray(Charsets.UTF_16LE)
        return hash(String(unicode, Charsets.ISO_8859_1), "MD4")
    }
}

class CryptoTools {

    private val secureRandom = SecureRandom()

    // Base64 encoding/decoding
    fun base64Encode(input: String): String {
        return Base64.encodeToString(input.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    fun base64Decode(input: String): String {
        return try {
            String(Base64.decode(input, Base64.DEFAULT), Charsets.UTF_8)
        } catch (e: Exception) {
            "Invalid Base64"
        }
    }

    // Hex encoding/decoding
    fun hexEncode(input: String): String {
        return input.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }
    }

    fun hexDecode(input: String): String {
        return try {
            input.chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
                .toString(Charsets.UTF_8)
        } catch (e: Exception) {
            "Invalid Hex"
        }
    }

    // URL encoding/decoding
    fun urlEncode(input: String): String {
        return java.net.URLEncoder.encode(input, "UTF-8")
    }

    fun urlDecode(input: String): String {
        return try {
            java.net.URLDecoder.decode(input, "UTF-8")
        } catch (e: Exception) {
            "Invalid URL encoding"
        }
    }

    // ROT13
    fun rot13(input: String): String {
        return input.map { char ->
            when {
                char in 'a'..'z' -> 'a' + (char - 'a' + 13) % 26
                char in 'A'..'Z' -> 'A' + (char - 'A' + 13) % 26
                else -> char
            }
        }.joinToString("")
    }

    // AES Encryption
    fun aesEncrypt(plaintext: String, password: String): String {
        val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
        val iv = ByteArray(16).also { secureRandom.nextBytes(it) }
        
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
        val secretKey = SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        
        // Combine salt + iv + encrypted
        val combined = salt + iv + encrypted
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun aesDecrypt(ciphertext: String, password: String): String {
        return try {
            val combined = Base64.decode(ciphertext, Base64.DEFAULT)
            
            val salt = combined.sliceArray(0..15)
            val iv = combined.sliceArray(16..31)
            val encrypted = combined.sliceArray(32 until combined.size)
            
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
            val secretKey = SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
            
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            
            String(cipher.doFinal(encrypted), Charsets.UTF_8)
        } catch (e: Exception) {
            "Decryption failed: ${e.message}"
        }
    }

    // Password Generator
    fun generatePassword(
        length: Int = 16,
        includeUppercase: Boolean = true,
        includeLowercase: Boolean = true,
        includeNumbers: Boolean = true,
        includeSymbols: Boolean = true
    ): String {
        val chars = StringBuilder()
        if (includeUppercase) chars.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        if (includeLowercase) chars.append("abcdefghijklmnopqrstuvwxyz")
        if (includeNumbers) chars.append("0123456789")
        if (includeSymbols) chars.append("!@#\$%^&*()_+-=[]{}|;:,.<>?")
        
        if (chars.isEmpty()) chars.append("abcdefghijklmnopqrstuvwxyz")
        
        return (1..length)
            .map { chars[secureRandom.nextInt(chars.length)] }
            .joinToString("")
    }

    // Password Strength Checker
    fun checkPasswordStrength(password: String): PasswordStrength {
        var score = 0
        
        // Length
        score += when {
            password.length >= 16 -> 25
            password.length >= 12 -> 20
            password.length >= 8 -> 15
            password.length >= 6 -> 10
            else -> 5
        }
        
        // Character variety
        if (password.any { it.isUpperCase() }) score += 15
        if (password.any { it.isLowerCase() }) score += 15
        if (password.any { it.isDigit() }) score += 15
        if (password.any { !it.isLetterOrDigit() }) score += 20
        
        // Patterns (negative)
        if (password.contains(Regex("(.)\\1{2,}"))) score -= 10 // Repeated chars
        if (password.contains(Regex("(?i)(password|123456|qwerty)"))) score -= 25
        
        val rating = when {
            score >= 80 -> "Strong"
            score >= 60 -> "Good"
            score >= 40 -> "Fair"
            score >= 20 -> "Weak"
            else -> "Very Weak"
        }
        
        return PasswordStrength(score.coerceIn(0, 100), rating)
    }

    data class PasswordStrength(val score: Int, val rating: String)

    // JWT Decoder
    fun decodeJWT(token: String): JWTResult {
        return try {
            val parts = token.split(".")
            if (parts.size != 3) {
                return JWTResult(null, null, "Invalid JWT format")
            }
            
            val header = String(Base64.decode(parts[0], Base64.URL_SAFE), Charsets.UTF_8)
            val payload = String(Base64.decode(parts[1], Base64.URL_SAFE), Charsets.UTF_8)
            
            JWTResult(header, payload, null)
        } catch (e: Exception) {
            JWTResult(null, null, "Failed to decode: ${e.message}")
        }
    }

    data class JWTResult(val header: String?, val payload: String?, val error: String?)
}

class PasswordCracker {
    
    private val hashTools = HashTools()
    private var isPremium = false
    
    interface CrackListener {
        fun onProgress(tried: Int, total: Int)
        fun onFound(password: String, hash: String)
        fun onNotFound()
    }
    
    suspend fun dictionaryAttack(
        hash: String,
        hashType: String,
        wordlist: List<String>,
        listener: CrackListener
    ) {
        val maxAttempts = if (isPremium) wordlist.size else minOf(wordlist.size, 1000)
        
        for ((index, word) in wordlist.take(maxAttempts).withIndex()) {
            val testHash = hashTools.hash(word, hashType)
            
            if (testHash.equals(hash, ignoreCase = true)) {
                listener.onFound(word, hash)
                return
            }
            
            if (index % 100 == 0) {
                listener.onProgress(index, maxAttempts)
            }
        }
        
        listener.onNotFound()
    }
    
    fun setPremium(premium: Boolean) {
        isPremium = premium
    }
}
